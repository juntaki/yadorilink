//! `MaterializationStateRepository` owns the on-demand-sync placeholder-
//! lifecycle subset of the `files` table: `materialization_state` itself,
//! held state, and the block-liveness/eviction-candidate queries that key
//! off it. Shares the same `files` table (and the same `Arc<SyncDatabase>`
//! shape) as the sibling [`crate::file_index::FileIndexRepository`], which
//! owns plain file-record CRUD instead -- a responsibility split, not a
//! storage boundary, per `docs/design/syncstate-repository-ownership.md`.
//!
//! Moved out of `yadorilink-sync-core` in Phase 7D-9C, following the exact
//! precedent `dirty_path.rs`'s own move already established.

use std::collections::HashSet;
use std::sync::Arc;

use rusqlite::OptionalExtension;

use crate::error::SyncSqliteError;
use yadorilink_filesystem_sync::materialization_types::EvictableFile;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::{HeldState, MaterializationState};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

/// Content-addressed block hash, hex-encoded. Deliberately duplicated here
/// rather than depending on another crate solely for this alias -- same
/// "duplicate small leaf types rather than force an awkward shared
/// dependency" precedent `yadorilink-local-storage::traits::ContentHash`
/// and `yadorilink-sync-core::index::ContentHash` already established
/// independently of each other.
pub type ContentHash = String;

/// Mirrors `peer_session::disk_race_fingerprint`'s own `(len, mtime, ctime,
/// ctime_nsec)` return shape as a plain tuple, so this lower-level crate
/// doesn't need a dependency on `yadorilink-peer-session` just for a type
/// alias -- see [`MaterializationStateRepository::record_materialized_
/// fingerprint`]'s own doc comment for what this identifies.
pub type MaterializedFingerprint = (u64, Option<std::time::SystemTime>, i64, i64);

/// Counts of non-deleted files in a group by materialization state --
/// `yadorilink status`'s per-folder summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MaterializationCounts {
    pub hydrated: u64,
    pub placeholder: u64,
    pub hydrating: u64,
}

pub struct MaterializationStateRepository {
    database: Arc<SyncDatabase>,
}

impl MaterializationStateRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    pub fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let state: Option<String> = conn
                .query_row(
                    "SELECT materialization_state FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(state.as_deref().map(MaterializationState::from_db_str))
        })
    }

    pub fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            Ok(conn.execute(
                "UPDATE files SET materialization_state = ?1 \
                 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![state.as_db_str(), group_id, path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    /// `_in_tx` counterpart of [`Self::set_materialization_state`], for a
    /// caller that already holds an open transaction spanning more writes
    /// than just this one (C4-6: bounded batching of receiver-side
    /// materialization commits) -- see `open_projected_upserts_batch`'s own
    /// call site for why it needs this: the row it just upserted no longer
    /// gets `Hydrated` from the schema's own column default (v25 changed
    /// that default to `Placeholder` -- see `SCHEMA_VERSION`'s doc comment),
    /// so a caller that deliberately wants `Hydrated`-with-an-open-intent
    /// (the established crash-recoverable shape for a batched candidate
    /// whose disk publish has not landed yet) must say so explicitly now,
    /// same as every other caller of this pattern. Does not error on zero
    /// rows affected the way the non-`_in_tx` version above does -- the
    /// row was just upserted by this same transaction, so a miss here would
    /// indicate a logic error in the caller, not a legitimate "not found."
    pub fn set_materialization_state_in_tx(
        tx: &rusqlite::Transaction,
        group_id: &str,
        path: &str,
        state: MaterializationState,
    ) -> Result<(), SyncSqliteError> {
        tx.execute(
            "UPDATE files SET materialization_state = ?1 \
             WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
            rusqlite::params![state.as_db_str(), group_id, path],
        )?;
        Ok(())
    }

    /// Atomically changes a current file's materialization state only when
    /// it still matches `expected`. Cleanup guards use this to avoid rolling
    /// back a newer transition performed by another operation.
    pub fn transition_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        next: MaterializationState,
        permit: &RootCommitPermit,
    ) -> Result<bool, SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            Ok(conn.execute(
                "UPDATE files SET materialization_state = ?1 \
                 WHERE group_id = ?2 AND path = ?3 AND state = 'current' \
                   AND materialization_state = ?4",
                rusqlite::params![next.as_db_str(), group_id, path, expected.as_db_str()],
            )?)
        })?;
        Ok(affected == 1)
    }

    /// Like `transition_materialization_state`, but also requires the
    /// `current` row's `authoring_change_hash` to still match
    /// `expected_authoring_hash` — a plain state-only CAS is not enough to
    /// tell "this row is still the same version this caller started
    /// working on, just still `Hydrating`" apart from "a NEWER version of
    /// this same path became `current`, and happened to also land in
    /// `Hydrating` before this caller's cleanup ran" (e.g. a peer's
    /// concurrent update superseding the row mid-hydration). A cleanup
    /// guard bounding a hydration attempt uses this, not the plain
    /// version, to avoid rolling back a materialization state that
    /// belongs to a different, later version than the one it started
    /// with — see `HydratingStateGuard`'s own doc comment.
    pub fn transition_materialization_state_if_same_authoring(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        expected_authoring_hash: Option<&ChangeHash>,
        next: MaterializationState,
    ) -> Result<bool, SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(match expected_authoring_hash {
                Some(hash) => conn.execute(
                    "UPDATE files SET materialization_state = ?1 \
                     WHERE group_id = ?2 AND path = ?3 AND state = 'current' \
                       AND materialization_state = ?4 AND authoring_change_hash = ?5",
                    rusqlite::params![
                        next.as_db_str(),
                        group_id,
                        path,
                        expected.as_db_str(),
                        &hash.0[..],
                    ],
                )?,
                None => conn.execute(
                    "UPDATE files SET materialization_state = ?1 \
                     WHERE group_id = ?2 AND path = ?3 AND state = 'current' \
                       AND materialization_state = ?4 AND authoring_change_hash IS NULL",
                    rusqlite::params![next.as_db_str(), group_id, path, expected.as_db_str()],
                )?,
            })
        })?;
        Ok(affected == 1)
    }

    /// `Hydrating` is set right before a block fetch begins
    /// (`peer_session.rs`/`hydration.rs`) and only ever reset back on that
    /// same call's own failure paths — if the process is killed in
    /// between (crash, force-quit, power loss), the row stays
    /// `Hydrating` forever. A stuck `Hydrating` file is excluded from
    /// eviction *and* `build_record_for_created_or_modified` refuses to
    /// chunk it, so a real local edit to that path is silently ignored
    /// until something happens to re-hydrate it — which nothing will,
    /// since nothing believes it's still a placeholder. Called once at
    /// daemon startup (never mid-run, since a live daemon's own
    /// `Hydrating` rows are legitimately in progress) to reset every
    /// stale `Hydrating` row, across every group, back to `Placeholder`
    /// — safe because `Placeholder` just means "not fetched yet," and a
    /// startup is definitionally after any hydration that was running
    /// crashed with it.
    pub fn reset_stale_hydrating_to_placeholder(&self) -> Result<usize, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE files SET materialization_state = ?1 \
                 WHERE materialization_state = ?2 AND state = 'current'",
                rusqlite::params![
                    MaterializationState::Placeholder.as_db_str(),
                    MaterializationState::Hydrating.as_db_str()
                ],
            )?)
        })
    }

    /// `Evicting` is set right before eviction writes the placeholder and is
    /// cleared to `Placeholder` only once that placeholder is committed
    /// (`materialization_eviction::evict_file`). A crash in that window
    /// leaves the row `Evicting` forever: `reset_stale_hydrating_to_placeholder`
    /// above touches only `Hydrating` rows, `repair_interrupted_materializations`
    /// skips every non-`Hydrated` row, and nothing else reconciles it — so
    /// the file is permanently wedged (status even miscounts it as
    /// hydrating). No blocks are ever lost: physical block reclamation
    /// happens only *after* the row has already transitioned to
    /// `Placeholder`, so an `Evicting` row is guaranteed to still have every
    /// block retained. Called once at daemon startup (never mid-run, since a
    /// live daemon's own `Evicting` rows are legitimately an eviction in
    /// progress) to reset every stale `Evicting` row back to `Placeholder`
    /// — the same target, and the same blanket-UPDATE discipline, as the
    /// `Hydrating` reset above, chosen because it is safe for both
    /// interrupted-eviction disk states:
    ///
    /// - If the placeholder was already written before the crash, the row is
    ///   now `Placeholder` over a placeholder file on disk — identical to a
    ///   normally completed eviction (blocks retained), which every other path
    ///   already handles.
    /// - If the crash landed *before* the placeholder write, the real content
    ///   is still fully on disk under a `Placeholder` row. This is the safe
    ///   direction of divergence: `Placeholder` means "re-fetch/verify before
    ///   trusting", so the content is preserved untouched on disk and the
    ///   ordinary hydrate/read path reconciles it later (peer-free, since the
    ///   blocks are retained) — no data loss and no spurious conflict copy.
    ///
    /// Resetting to `Hydrated` instead would be unsafe: for the first sub-case,
    /// `repair_interrupted_materializations` would see a `Hydrated` row whose
    /// on-disk bytes (the zero-filled placeholder) do not match the indexed
    /// blocks, quarantine that placeholder as a divergent "user edit", and
    /// journal it as a new local path — fabricating a zero-filled conflict copy.
    pub fn reset_stale_evicting_to_placeholder(&self) -> Result<usize, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE files SET materialization_state = ?1 \
                 WHERE materialization_state = ?2 AND state = 'current'",
                rusqlite::params![
                    MaterializationState::Placeholder.as_db_str(),
                    MaterializationState::Evicting.as_db_str()
                ],
            )?)
        })
    }

    /// Hydrated, unpinned, non-deleted files for `group_id`, ordered
    /// least-recently-accessed first (files never accessed sort before
    /// any that have been, per `NULLS FIRST`) — the automatic eviction
    /// sweep's candidate list, in eviction order.
    pub fn list_evictable_files(
        &self,
        group_id: &str,
    ) -> Result<Vec<EvictableFile>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, size, last_accessed_unix FROM files
                 WHERE group_id = ?1 AND state = 'current' AND deleted = 0 AND pinned = 0
                    AND materialization_state = 'hydrated'
                 ORDER BY last_accessed_unix ASC NULLS FIRST",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok(EvictableFile {
                    path: r.get(0)?,
                    size: r.get(1)?,
                    last_accessed_unix: r.get(2)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Total on-disk size of every hydrated, non-deleted file in
    /// `group_id`, pinned or not. `list_evictable_files` above
    /// deliberately excludes pinned files since they're never eviction
    /// *candidates* — but a pinned-and-hydrated file still occupies real
    /// disk space, so summing only `list_evictable_files`' sizes to
    /// gauge current usage against a folder's disk-usage cap
    /// systematically undercounts it, letting the sweep stop early and
    /// leave usage above the configured cap. Use this for the usage
    /// figure; keep using `list_evictable_files` for which files may
    /// actually be evicted.
    pub fn hydrated_usage_bytes(&self, group_id: &str) -> Result<u64, SyncSqliteError> {
        let total: Option<i64> = self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT SUM(size) FROM files
                 WHERE group_id = ?1 AND state = 'current' AND deleted = 0
                    AND materialization_state = 'hydrated'",
                [group_id],
                |r| r.get(0),
            )?)
        })?;
        Ok(total.unwrap_or(0).max(0) as u64)
    }

    /// Counts of non-deleted files in `group_id` by materialization state
    /// — `yadorilink status`'s per-folder summary, avoiding
    /// dumping every individual file path for what's meant to be a
    /// glance-able overview (matching how `conflict_count` already
    /// summarizes rather than lists).
    pub fn materialization_counts(
        &self,
        group_id: &str,
    ) -> Result<MaterializationCounts, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT materialization_state, COUNT(*) FROM files
                 WHERE group_id = ?1 AND state = 'current' AND deleted = 0
                 GROUP BY materialization_state",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })?;
            let mut counts = MaterializationCounts::default();
            for row in rows {
                let (state, count) = row?;
                match MaterializationState::from_db_str(&state) {
                    MaterializationState::Hydrated => counts.hydrated = count,
                    MaterializationState::Placeholder => counts.placeholder = count,
                    MaterializationState::Hydrating => counts.hydrating = count,
                    MaterializationState::Evicting => counts.hydrating += count,
                }
            }
            Ok(counts)
        })
    }

    /// Bulk-loads every non-deleted file's materialization state for
    /// `group_id` (batch processing) — used by
    /// `LocalChangeProcessor::scan_existing_files` so deciding whether an
    /// on-disk entry is a placeholder (which must never be chunked) costs
    /// one query for the whole scan instead of one per file.
    pub fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashMap<String, MaterializationState>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, materialization_state FROM files \
                 WHERE group_id = ?1 AND deleted = 0 AND state = 'current'",
            )?;
            let rows = stmt
                .query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            let mut out = std::collections::HashMap::new();
            for row in rows {
                let (path, state) = row?;
                out.insert(path, MaterializationState::from_db_str(&state));
            }
            Ok(out)
        })
    }

    /// Block hashes (hex) that back content this device is holding
    /// materialized on disk right now for `group_id`: every block referenced
    /// by a non-deleted, current file that is either hydrated or pinned.
    ///
    /// These blocks must never be reclaimed as on-demand cache — dropping one
    /// would corrupt a file whose bytes are supposed to be present on disk.
    /// Eviction uses this set to compute which of an evicted file's blocks are
    /// safe to reclaim: only blocks NOT in this set (i.e. no longer backing any
    /// locally-present file) may be freed, and only then after full-replica
    /// custody is confirmed. A block that is still shared with another
    /// hydrated/pinned file stays; a block referenced only by placeholdered
    /// (non-hydrated) files is reclaimable because that content is re-fetched
    /// on demand.
    pub fn blocks_backing_local_content(
        &self,
        group_id: &str,
    ) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT blocks_json FROM files \
                 WHERE group_id = ?1 AND deleted = 0 AND state = 'current' \
                   AND (materialization_state = 'hydrated' OR pinned = 1)",
            )?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
            let mut needed: HashSet<ContentHash> = HashSet::new();
            for row in rows {
                let blocks: Vec<BlockInfo> = serde_json::from_str(&row?)?;
                needed.extend(blocks.into_iter().map(|block| hex::encode(block.hash)));
            }
            Ok(needed)
        })
    }

    /// Block hashes referenced by any retained row other than the exact
    /// current row being considered for cache eviction. The block store is
    /// device-global, so this scan crosses groups and includes placeholder,
    /// superseded, and trashed rows. A placeholder elsewhere may still retain
    /// the only local copy because its own custody check failed.
    pub fn blocks_referenced_outside_current_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT blocks_json FROM files \
                 WHERE deleted = 0 \
                   AND NOT (group_id = ?1 AND path = ?2 AND state = 'current')",
            )?;
            let rows = stmt.query_map([group_id, path], |r| r.get::<_, String>(0))?;
            let mut referenced = HashSet::new();
            for row in rows {
                let blocks: Vec<BlockInfo> = serde_json::from_str(&row?)?;
                referenced.extend(blocks.into_iter().map(|block| hex::encode(block.hash)));
            }
            Ok(referenced)
        })
    }

    /// Paths whose own index row already admits it has no bytes: an eager or
    /// pinned `placeholder`, or a `hydrating` row abandoned mid-fetch.
    /// `peer_session::reconcile_local_materialization_audit` re-drives exactly
    /// these through an ordinary peer fetch.
    ///
    /// Deliberately NOT selected, and this must stay that way: a `hydrated` row
    /// whose bytes are missing from disk. That divergence is real, but it is
    /// not repairable from here, because two causes produce a byte-identical
    /// index row —
    ///
    ///   * a crash between the durable `Hydrated` commit and the
    ///     temp-write-then-rename that was meant to follow it, which should be
    ///     reconstructed; and
    ///   * the user deleting or renaming the file away while the daemon was
    ///     stopped, which must NOT be reconstructed.
    ///
    /// The only thing separating them is the durable `materialization_intents`
    /// journal: the crash leaves an intent open, the offline delete does not
    /// (the intent seam in `peer_session`'s `materialize` carries a
    /// `debug_assert!` that no `Hydrated` row is ever committed for a
    /// not-yet-written file without one, which is what makes the journal's
    /// absence meaningful rather than merely unproven). Joining that journal in
    /// here would not rescue the query either: every path returned is fed
    /// straight to `rematerialize_local_records`, which rewrites the file
    /// unconditionally — so widening to `hydrated` silently resurrects the
    /// user's deletion, and the narrow with-intent subset would still be
    /// repaired against the wrong evidence, since this is a query over the
    /// `files` table and "absent from disk" is not a fact it can observe.
    ///
    /// Nor may the caller supply that fact by stat'ing the paths: it holds no
    /// `yadorilink_root_authority::root_identity::VerifiedRoot`, and an
    /// unmounted volume leaves its mountpoint behind, so `metadata` succeeds
    /// and every `hydrated` file in the group looks absent at once.
    ///
    /// So `hydrated`-with-no-bytes is owned by
    /// `materialization_repair::repair_interrupted_materializations`, which
    /// holds both missing pieces — it takes a `VerifiedRoot`, and it branches
    /// on the intent journal, reconstructing the crash and classifying the
    /// offline delete as a deletion instead of healing it. The daemon runs
    /// that pass at startup and on a live periodic per-link cadence, and the
    /// startup disk-reconcile scan emits the resulting tombstone. This is a
    /// division of labor, not a gap in it: rows that know they need bytes are
    /// repaired over the network from here; rows that disagree with disk are
    /// repaired against disk there.
    pub fn list_materialization_repair_candidates(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                // `l.orphaned = 0` keeps this fail-closed at the storage layer: an
                // orphaned link's coordination-side authorization is permanently
                // gone, so none of its files are ever repair-eligible. The daemon
                // scheduler already filters orphaned links before calling this, but
                // the core query must not depend on that to stay correct.
                "SELECT f.path FROM files f \
                 JOIN links l ON l.group_id = f.group_id \
                 WHERE f.group_id = ?1 \
                   AND l.orphaned = 0 \
                   AND f.deleted = 0 \
                   AND f.state = 'current' \
                   AND ( \
                     (f.materialization_state = 'placeholder' AND l.materialization_policy = \
                      'eager') \
                     OR (f.materialization_state = 'placeholder' AND f.pinned = 1) \
                     OR f.materialization_state = 'hydrating' \
                   ) \
                 ORDER BY f.path",
            )?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
    }

    /// Records that `peer_device_id` EXPLICITLY, definitively refused a
    /// fetch of `path` AT `version_hash` for lack of verified provenance on
    /// that exact version -- see `block_fetch_refusals`'s own schema doc
    /// comment for why this is deliberately distinct both from a transient
    /// miss and from any other rejection reason (never recorded here), and
    /// why it is bound to the exact version rather than just the path.
    /// Idempotent per `(group_id, path, version_hash, peer_device_id)`: a
    /// fresh rejection overwrites whatever was recorded before.
    pub fn record_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
        peer_device_id: &str,
        reason: &str,
        now_unix_nanos: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO block_fetch_refusals \
                     (group_id, path, version_hash, peer_device_id, reason, refused_at_unix_nanos) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(group_id, path, version_hash, peer_device_id) DO UPDATE SET \
                     reason = excluded.reason, \
                     refused_at_unix_nanos = excluded.refused_at_unix_nanos",
                rusqlite::params![
                    group_id,
                    path,
                    version_hash,
                    peer_device_id,
                    reason,
                    now_unix_nanos
                ],
            )?;
            Ok(())
        })
    }

    /// Deletes any refusal previously recorded for `peer_device_id` against
    /// `path` at `version_hash` -- called on a SUCCESSFUL fetch, so a peer
    /// that once refused a version but has since obtained it can never be
    /// read as still refusing it. Refusals for OTHER versions of the same
    /// path are untouched (they were never evidence about this version to
    /// begin with, since the table is version-scoped).
    pub fn clear_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
        peer_device_id: &str,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM block_fetch_refusals \
                 WHERE group_id = ?1 AND path = ?2 AND version_hash = ?3 AND peer_device_id = ?4",
                rusqlite::params![group_id, path, version_hash, peer_device_id],
            )?;
            Ok(())
        })
    }

    /// Every peer device id that has EXPLICITLY refused `path` AT the exact
    /// `version_hash` (not merely never been asked, not a transient miss,
    /// and not a refusal recorded against some OTHER version of this path)
    /// -- the evidence `known_unobtainable_required_content` cross-
    /// references against the group's current authorized-writer set to
    /// positively confirm no currently-reachable peer can serve the CURRENT
    /// version's content, rather than inferring it from connectivity/timing
    /// alone or conflating it with a since-superseded version's refusals.
    pub fn refusing_peers_for_path(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
    ) -> Result<std::collections::HashSet<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT peer_device_id FROM block_fetch_refusals \
                 WHERE group_id = ?1 AND path = ?2 AND version_hash = ?3",
            )?;
            let rows = stmt.query_map(rusqlite::params![group_id, path, version_hash], |r| {
                r.get::<_, String>(0)
            })?;
            let mut out = std::collections::HashSet::new();
            for row in rows {
                out.insert(row?);
            }
            Ok(out)
        })
    }

    /// Bare `files`-table live set, with no `dag_retention_roots`
    /// contribution — kept for callers (this module's own tests, an
    /// explicit per-group check) that want exactly that. Physical
    /// block-store GC must use
    /// [`live_block_hashes_including_all_dag_retention_roots`](Self::live_block_hashes_including_all_dag_retention_roots)
    /// instead: a `full_payload`-rooted change's blocks are not necessarily
    /// reachable through any `files` row yet (`captured_authoring` writes a
    /// `file_versions`/`change_file_versions` row, not a `files` row, at
    /// authoring time — see that module), so this bare query alone does not
    /// protect them.
    pub fn live_block_hashes(&self) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        self.live_block_hashes_with_extra_roots(std::iter::empty())
    }

    /// [`live_block_hashes`](Self::live_block_hashes), plus every block a
    /// `full_payload` [`crate::dag_store::register_retention_root`] entry
    /// requires kept for `group_id` -- the shared-retention-root extension
    /// point [`live_block_hashes_with_extra_roots`](Self::live_block_hashes_with_extra_roots)'s
    /// own doc comment names. Single-group form, for a caller that already
    /// scopes its own work to one group; physical block-store GC sweeps the
    /// one block store shared by every group in one pass and should use
    /// [`live_block_hashes_including_all_dag_retention_roots`](Self::live_block_hashes_including_all_dag_retention_roots)
    /// instead.
    pub fn live_block_hashes_including_dag_retention_roots(
        &self,
        group_id: &str,
    ) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        let extra_roots = self
            .database
            .read(|conn| crate::dag_store::full_payload_retained_block_hashes(conn, group_id))?;
        self.live_block_hashes_with_extra_roots(extra_roots)
    }

    /// The live set every physical block-store GC sweep must use:
    /// [`live_block_hashes`](Self::live_block_hashes) unioned with every
    /// `full_payload` [`crate::dag_store::register_retention_root`] entry
    /// registered in *any* group. `yadorilink-daemon`'s sweep
    /// (`gc::run_sweep_sync`) is the one production caller — it deletes
    /// content-addressed block bytes daemon-wide, not per group, so it needs
    /// the union across every group in one query rather than iterating
    /// `live_block_hashes_including_dag_retention_roots` once per link:
    /// iterating links would also miss a group whose retention root outlived
    /// its link (an orphaned or already-removed link must not silently drop
    /// protection for a root some other subsystem is still holding).
    pub fn live_block_hashes_including_all_dag_retention_roots(
        &self,
    ) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        let extra_roots = self.database.read::<_, SyncSqliteError>(
            crate::dag_store::full_payload_retained_block_hashes_all_groups,
        )?;
        self.live_block_hashes_with_extra_roots(extra_roots)
    }

    /// Computes the GC live set from one SQLite snapshot and appends
    /// caller-provided roots. The extra-root hook is intentionally generic
    /// so a future version-history/trash table can contribute retained
    /// blocks without changing `live_block_hashes` again.
    ///
    /// This query is
    /// deliberately **not** filtered by `state` — every row with
    /// `deleted = 0` contributes its blocks regardless of whether it is
    /// `current`, `superseded`, or `trashed`, which is exactly the live-root
    /// contract a future block-store GC must honor (a block referenced by
    /// any retained version, not only the current one, is live). A
    /// `deleted = 1` row's own `blocks_json` is always `[]` (see
    /// `upsert_file_in_tx`/`mark_deleted`), so excluding it changes nothing
    /// — the *prior* live content a delete superseded is retained under
    /// `state = 'trashed'` with `deleted = 0`, and is therefore still
    /// scanned here. No code changes to `BlockStore` itself are required by
    /// this change (`delete` is still never called); this comment and
    /// `live_block_hashes_include_superseded_and_trashed_blocks` below are
    /// the load-bearing documentation of that contract for a future
    /// block-store GC implementation.
    pub fn live_block_hashes_with_extra_roots(
        &self,
        extra_roots: impl IntoIterator<Item = ContentHash>,
    ) -> Result<HashSet<ContentHash>, SyncSqliteError> {
        // Read-only multi-statement snapshot -- see
        // `RecoverySnapshotReader::recovery_local_snapshot`'s doc comment for
        // why `unchecked_transaction` (built from `read`'s plain `&Connection`)
        // is the right tool here instead of `write`/`write_immediate`: nothing
        // in this scan ever mutates `files`.
        let extra_roots: Vec<ContentHash> = extra_roots.into_iter().collect();
        self.database.read::<_, SyncSqliteError>(|conn| {
            let tx = conn.unchecked_transaction()?;
            let mut live: HashSet<ContentHash> = extra_roots.iter().cloned().collect();
            {
                let mut stmt = tx.prepare("SELECT blocks_json FROM files WHERE deleted = 0")?;
                let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
                for row in rows {
                    let blocks: Vec<BlockInfo> = serde_json::from_str(&row?)?;
                    live.extend(blocks.into_iter().map(|block| hex::encode(block.hash)));
                }
            }
            tx.commit()?;
            Ok(live)
        })
    }

    /// A held file's reason and hold timestamp, so both
    /// survive a daemon restart. `None` if the row isn't currently held
    /// (either no row, or a row with no `held_reason` recorded) — the two
    /// columns are only ever written/cleared together (`set_held`/
    /// `clear_held`), so they can't independently be half-set.
    pub fn get_held_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<HeldState>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row: Option<(Option<String>, Option<i64>)> = conn
                .query_row(
                    "SELECT held_reason, held_since_unix_nanos FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            Ok(row.and_then(|(reason, since_unix_nanos)| match (reason, since_unix_nanos) {
                (Some(reason), Some(since_unix_nanos)) => {
                    Some(HeldState { reason, since_unix_nanos })
                }
                _ => None,
            }))
        })
    }

    /// Marks a file held with `reason` (e.g. `"case_collision"`,
    /// `"invalid_name"` — a free-form reason string, not a closed enum, so
    /// the hazard-detection logic that actually decides these reasons
    /// isn't constrained by this schema-only task) as of `since_unix_nanos`.
    /// Held state is purely local — a held file's index row keeps
    /// participating in normal index exchange with peers; this
    /// column is never sent over the wire.
    pub fn set_held(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
        since_unix_nanos: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let affected = conn.execute(
                "UPDATE files SET held_reason = ?1, held_since_unix_nanos = ?2 \
                 WHERE group_id = ?3 AND path = ?4 AND state = 'current'",
                rusqlite::params![reason, since_unix_nanos, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// Every currently-held path in `group_id` — the candidate set for a
    /// periodic hazard re-check sweep. Nothing today re-evaluates a held
    /// path's hazard on its own once the SIBLING path that caused the
    /// collision changes (deleted, renamed, or itself re-admitted under a
    /// name that no longer collides): `clear_held` only ever runs as a side
    /// effect of a fresh incoming record for the SAME path, so a hold whose
    /// cause has already cleared can otherwise persist forever with no
    /// re-arm event. This listing exists to make that sweep possible; it is
    /// not itself the recheck.
    pub fn list_held_paths(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path FROM files \
                 WHERE group_id = ?1 AND state = 'current' AND held_reason IS NOT NULL",
            )?;
            let rows = stmt.query_map(rusqlite::params![group_id], |r| r.get::<_, String>(0))?;
            let mut paths = Vec::new();
            for row in rows {
                paths.push(row?);
            }
            Ok(paths)
        })
    }

    /// Clears a file's held state. A no-op, not an error, if the file
    /// wasn't held (or the row doesn't exist) — callers tombstoning a
    /// record don't first need to check whether it was ever held.
    pub fn clear_held(&self, group_id: &str, path: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "UPDATE files SET held_reason = NULL, held_since_unix_nanos = NULL \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
            )?;
            Ok(())
        })
    }

    /// `_in_tx` counterpart of [`Self::clear_held`], for a caller that
    /// already holds an open transaction spanning more writes than just
    /// this one (C4-6: bounded batching of receiver-side materialization
    /// commits). Identical SQL/semantics.
    pub fn clear_held_in_tx(
        tx: &rusqlite::Transaction,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        tx.execute(
            "UPDATE files SET held_reason = NULL, held_since_unix_nanos = NULL \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
            rusqlite::params![group_id, path],
        )?;
        Ok(())
    }

    /// Records the identity of the exact on-disk object a `write_placeholder`
    /// call just created for `group_id`/`path` (M1-2) — always paired with
    /// that same call's `Placeholder` state transition, never called on its
    /// own. `dev`/`ino` round-trip losslessly through SQLite's signed
    /// 64-bit `INTEGER` via a bit-pattern cast (`as i64`/`as u64`); the
    /// value is an opaque identity token, never interpreted as a signed
    /// number.
    pub fn record_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        identity: yadorilink_local_storage::PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            Ok(conn.execute(
                "UPDATE files SET placeholder_dev = ?1, placeholder_ino = ?2, \
                 placeholder_provider_kind = ?3 \
                 WHERE group_id = ?4 AND path = ?5 AND state = 'current'",
                rusqlite::params![
                    identity.dev as i64,
                    identity.ino as i64,
                    provider_kind,
                    group_id,
                    path
                ],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    /// M2-2: atomically "mint-or-read" a placeholder identity -- returns
    /// whatever identity `group_id`/`path` ends up recorded with, which is
    /// `candidate` if none was recorded yet for `provider_kind`, or the
    /// ALREADY-recorded one otherwise (`candidate` is then discarded,
    /// never written). Unlike calling `get_placeholder_generation` (a
    /// `database.read`, not serialized against this process's own writer
    /// lock) followed by a separate `record_placeholder_generation` call,
    /// this does the check-then-write in ONE `database.write` closure, so
    /// two callers racing to mint a generation for the same path (e.g. two
    /// concurrent `ListFolderFilesRequest` handlers) cannot both "win" --
    /// exactly the race an independent review found in the two-call
    /// pattern this replaces at its one call site
    /// (`LinkFlushHandle::ensure_windows_placeholder_generation`).
    ///
    /// Only compares against a currently-recorded identity whose
    /// `provider_kind` matches the one passed in -- a row already carrying
    /// a DIFFERENT provider's identity (e.g. `INTERNAL_INODE_PROVIDER_KIND`
    /// on a cross-platform-mismatched row) is treated as "nothing recorded
    /// for this provider yet" and overwritten with `candidate`, same as
    /// `record_placeholder_generation`'s own unconditional behavior always
    /// did for that case.
    pub fn record_placeholder_generation_if_absent(
        &self,
        group_id: &str,
        path: &str,
        candidate: yadorilink_local_storage::PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit,
    ) -> Result<yadorilink_local_storage::PlaceholderDiskIdentity, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            let existing: Option<(Option<i64>, Option<i64>, Option<String>)> = conn
                .query_row(
                    "SELECT placeholder_dev, placeholder_ino, placeholder_provider_kind \
                     FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            if let Some((Some(dev), Some(ino), Some(existing_kind))) = existing {
                if existing_kind == provider_kind {
                    return Ok(yadorilink_local_storage::PlaceholderDiskIdentity {
                        dev: dev as u64,
                        ino: ino as u64,
                    });
                }
            }
            let affected = conn.execute(
                "UPDATE files SET placeholder_dev = ?1, placeholder_ino = ?2, \
                 placeholder_provider_kind = ?3 \
                 WHERE group_id = ?4 AND path = ?5 AND state = 'current'",
                rusqlite::params![
                    candidate.dev as i64,
                    candidate.ino as i64,
                    provider_kind,
                    group_id,
                    path
                ],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(candidate)
        })
    }

    /// Clears any placeholder identity recorded for `group_id`/`path` — a
    /// no-op, not an error, if none was recorded (or the row doesn't
    /// exist). Callers use this whenever a path stops being a placeholder
    /// this process can vouch for: `write_placeholder` returning `None`
    /// (no identity capturable on this platform — see that function's own
    /// doc comment) must not leave a PRIOR call's identity behind to be
    /// wrongly trusted against the new placeholder's bytes, and a
    /// transition out of `Placeholder` (hydrate, or a confirmed local
    /// edit) leaves a stale identity with nothing left to identify.
    pub fn clear_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            conn.execute(
                "UPDATE files SET placeholder_dev = NULL, placeholder_ino = NULL, \
                 placeholder_provider_kind = NULL \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
            )?;
            Ok(())
        })
    }

    /// The placeholder identity recorded for `group_id`/`path`, if any.
    /// `None` — a row with no identity recorded, a row that isn't
    /// currently a placeholder at all, or no row — is not "unknown, treat
    /// as untouched": every caller of this method must treat it exactly
    /// like a later identity mismatch (fail closed), never like a
    /// confirmed match. See `crate::local_change`'s (yadorilink-local-capture)
    /// own dirty-detection doc comment for why.
    ///
    /// Deliberately filtered to `materialization_state = 'placeholder'`,
    /// not merely `placeholder_dev IS NOT NULL`: no production call site
    /// clears a row's identity on every transition OUT of `Placeholder`
    /// today (only `write_placeholder` returning `None` clears it, when a
    /// fresh placeholder write captured no identity) -- an independent
    /// review's finding. Without this filter, a file hydrated after being
    /// a placeholder would keep exposing its now-meaningless prior
    /// identity here, which a caller comparing against a freshly-observed
    /// disk object could wrongly read as "matches, still untouched" even
    /// though the row no longer describes a placeholder at all. Gating the
    /// read on the row's own current state closes this at the one seam
    /// every caller already goes through, without needing every hydrate/
    /// transition call site across the codebase to remember to also call
    /// `clear_placeholder_generation`.
    pub fn get_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordedPlaceholderGeneration>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row: Option<(Option<i64>, Option<i64>, Option<String>)> = conn
                .query_row(
                    "SELECT placeholder_dev, placeholder_ino, placeholder_provider_kind \
                     FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
                       AND materialization_state = 'placeholder'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            Ok(row.and_then(|(dev, ino, provider_kind)| match (dev, ino, provider_kind) {
                (Some(dev), Some(ino), Some(provider_kind)) => {
                    Some(RecordedPlaceholderGeneration {
                        identity: yadorilink_local_storage::PlaceholderDiskIdentity {
                            dev: dev as u64,
                            ino: ino as u64,
                        },
                        provider_kind,
                    })
                }
                _ => None,
            }))
        })
    }

    /// Unlike [`Self::get_placeholder_generation`], NOT gated on
    /// `materialization_state = 'placeholder'` -- returns whatever identity
    /// is currently on the row regardless of state. No production call site
    /// clears `placeholder_dev`/`placeholder_ino`/`placeholder_provider_kind`
    /// on the `Placeholder` -> `Hydrated` transition (only an explicit
    /// [`Self::clear_placeholder_generation`] call does), so a `Hydrated`
    /// row still exposes the generation its placeholder identity was minted
    /// under here. M2-3b's Windows eviction path uses this -- reading a
    /// `Hydrated` file's own still-recorded generation as the expected
    /// identity for the native dehydrate call's defense-in-depth check --
    /// which is exactly the "now-meaningless prior identity" scenario
    /// [`Self::get_placeholder_generation`]'s own doc comment warns a
    /// dirty-detection caller must not read; the two accessors exist because
    /// the two callers need opposite answers to the same query.
    pub fn get_recorded_placeholder_identity(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordedPlaceholderGeneration>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row: Option<(Option<i64>, Option<i64>, Option<String>)> = conn
                .query_row(
                    "SELECT placeholder_dev, placeholder_ino, placeholder_provider_kind \
                     FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            Ok(row.and_then(|(dev, ino, provider_kind)| match (dev, ino, provider_kind) {
                (Some(dev), Some(ino), Some(provider_kind)) => {
                    Some(RecordedPlaceholderGeneration {
                        identity: yadorilink_local_storage::PlaceholderDiskIdentity {
                            dev: dev as u64,
                            ino: ino as u64,
                        },
                        provider_kind,
                    })
                }
                _ => None,
            }))
        })
    }

    /// Bulk-loads every non-deleted, still-a-placeholder file's identity
    /// for `group_id` in one query — the same batch-processing shape as
    /// [`list_materialization_states`](Self::list_materialization_states),
    /// for the same reason: `LocalChangeProcessor::scan_existing_files`
    /// must not pay one query per file to decide whether an on-disk entry
    /// is still its own untouched placeholder. Filtered to
    /// `materialization_state = 'placeholder'` for the same reason as
    /// [`get_placeholder_generation`](Self::get_placeholder_generation).
    pub fn list_placeholder_generations(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashMap<String, RecordedPlaceholderGeneration>, SyncSqliteError>
    {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, placeholder_dev, placeholder_ino, placeholder_provider_kind \
                 FROM files \
                 WHERE group_id = ?1 AND deleted = 0 AND state = 'current' \
                   AND materialization_state = 'placeholder' \
                   AND placeholder_dev IS NOT NULL AND placeholder_ino IS NOT NULL \
                   AND placeholder_provider_kind IS NOT NULL",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            let mut out = std::collections::HashMap::new();
            for row in rows {
                let (path, dev, ino, provider_kind) = row?;
                out.insert(
                    path,
                    RecordedPlaceholderGeneration {
                        identity: yadorilink_local_storage::PlaceholderDiskIdentity {
                            dev: dev as u64,
                            ino: ino as u64,
                        },
                        provider_kind,
                    },
                );
            }
            Ok(out)
        })
    }

    /// Every non-deleted, still-`Placeholder` path in `group_id` with NO
    /// recorded identity -- the exact crash window M1-2's own eviction
    /// call sites cannot close atomically: `write_placeholder` durably
    /// writes the sparse file, then a SEPARATE commit records its
    /// identity; a crash between the two leaves a row exactly like this.
    /// A caller (`materialization_repair::backfill_placeholder_
    /// generations`) uses this list to re-derive an identity for each
    /// path from its still-on-disk state at startup, before any watcher
    /// gets a chance to observe the row and (with no generation to
    /// compare against) fall through to treating the placeholder's own
    /// sparse bytes as a genuine local edit.
    pub fn list_placeholder_paths_missing_generation(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path FROM files \
                 WHERE group_id = ?1 AND deleted = 0 AND state = 'current' \
                   AND materialization_state = 'placeholder' \
                   AND placeholder_dev IS NULL",
            )?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// M5-A review follow-up (blocker #56): records the disk identity
    /// (`peer_session::disk_race_fingerprint`'s own `(len, mtime, ctime,
    /// ctime_nsec)` shape, passed here as a plain tuple to avoid this
    /// lower-level crate depending on `yadorilink-peer-session`) of the
    /// exact bytes this process JUST wrote via a successful
    /// `reconstruct_file`, alongside that same call's `Hydrated`
    /// transition. `None` (this platform/moment could not produce a
    /// fingerprint, or the just-written file's own `metadata()` call
    /// failed) clears every column to NULL rather than leaving a stale
    /// prior fingerprint behind -- same "never trust a fingerprint this
    /// exact write didn't itself confirm" discipline as `write_placeholder`
    /// returning `None` clearing `placeholder_dev`/`placeholder_ino`.
    pub fn record_materialized_fingerprint(
        &self,
        group_id: &str,
        path: &str,
        fingerprint: Option<MaterializedFingerprint>,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        let (len, mtime_nanos, ctime, ctime_nsec) = match fingerprint {
            Some((len, mtime, ctime, ctime_nsec)) => (
                Some(len as i64),
                mtime.and_then(|t| {
                    t.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_nanos() as i64)
                }),
                Some(ctime),
                Some(ctime_nsec),
            ),
            None => (None, None, None, None),
        };
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            conn.execute(
                "UPDATE files SET materialized_fingerprint_len = ?1, \
                 materialized_fingerprint_mtime_nanos = ?2, materialized_fingerprint_ctime = ?3, \
                 materialized_fingerprint_ctime_nsec = ?4 \
                 WHERE group_id = ?5 AND path = ?6 AND state = 'current'",
                rusqlite::params![len, mtime_nanos, ctime, ctime_nsec, group_id, path],
            )?;
            Ok(())
        })
    }

    /// `_in_tx` counterpart of [`Self::record_materialized_fingerprint`],
    /// for a caller that already holds an open transaction spanning more
    /// writes than just this one (C4-6: bounded batching of receiver-side
    /// materialization commits). Identical decomposition/SQL/semantics.
    pub fn record_materialized_fingerprint_in_tx(
        tx: &rusqlite::Transaction,
        group_id: &str,
        path: &str,
        fingerprint: Option<MaterializedFingerprint>,
    ) -> Result<(), SyncSqliteError> {
        let (len, mtime_nanos, ctime, ctime_nsec) = match fingerprint {
            Some((len, mtime, ctime, ctime_nsec)) => (
                Some(len as i64),
                mtime.and_then(|t| {
                    t.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_nanos() as i64)
                }),
                Some(ctime),
                Some(ctime_nsec),
            ),
            None => (None, None, None, None),
        };
        tx.execute(
            "UPDATE files SET materialized_fingerprint_len = ?1, \
             materialized_fingerprint_mtime_nanos = ?2, materialized_fingerprint_ctime = ?3, \
             materialized_fingerprint_ctime_nsec = ?4 \
             WHERE group_id = ?5 AND path = ?6 AND state = 'current'",
            rusqlite::params![len, mtime_nanos, ctime, ctime_nsec, group_id, path],
        )?;
        Ok(())
    }

    /// The materialized-content fingerprint recorded for `group_id`/`path`,
    /// if any -- `None` if no fingerprint was ever recorded (a pre-existing
    /// row from before this column existed, or a `Hydrated` row this
    /// device reached some other way than a verified `reconstruct_file`
    /// completing) OR the row is not currently `Hydrated`. Every caller
    /// must treat `None` as "not proven, do not trust the file's current
    /// bytes as untouched" -- the same fail-closed discipline
    /// [`Self::get_placeholder_generation`] documents for its own
    /// identical `materialization_state`-gated shape.
    pub fn get_materialized_fingerprint(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializedFingerprint>, SyncSqliteError> {
        type RawFingerprintRow = (Option<i64>, Option<i64>, Option<i64>, Option<i64>);
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row: Option<RawFingerprintRow> = conn
                .query_row(
                    "SELECT materialized_fingerprint_len, materialized_fingerprint_mtime_nanos, \
                     materialized_fingerprint_ctime, materialized_fingerprint_ctime_nsec \
                     FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
                       AND materialization_state = 'hydrated'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            Ok(row.and_then(|(len, mtime_nanos, ctime, ctime_nsec)| {
                let (len, ctime, ctime_nsec) = match (len, ctime, ctime_nsec) {
                    (Some(len), Some(ctime), Some(ctime_nsec)) => (len, ctime, ctime_nsec),
                    _ => return None,
                };
                let mtime = mtime_nanos.map(|nanos| {
                    std::time::UNIX_EPOCH + std::time::Duration::from_nanos(nanos as u64)
                });
                Some((len as u64, mtime, ctime, ctime_nsec))
            }))
        })
    }
}

/// A placeholder identity read back from storage, paired with which
/// identity scheme produced it -- `provider_kind` matters once more than
/// one scheme exists (a real OS provider's token is not comparable against
/// [`INTERNAL_INODE_PROVIDER_KIND`](yadorilink_local_storage::INTERNAL_INODE_PROVIDER_KIND)'s
/// `(dev, ino)` shape), so a caller must know which scheme it's holding
/// before comparing against a freshly-observed identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPlaceholderGeneration {
    pub identity: yadorilink_local_storage::PlaceholderDiskIdentity,
    pub provider_kind: String,
}

/// M5-A soak-closure durability investigation, review follow-up: a
/// reviewer's adversarial pass on the `known_unobtainable_required_content`
/// fix found the ORIGINAL `block_fetch_refusals` table keyed refusal
/// evidence by `(group_id, path, peer_device_id)` only -- no version
/// binding at all. That meant a refusal recorded against an OLDER version
/// of a path could be misread as evidence about a NEWER version that later
/// superseded it: author writes V1, a peer refuses V1 (recorded), the
/// author writes V2 (a distinct version, never refused by anyone) and then
/// leaves the group -- the OLD V1 refusal alone was enough to flip V2 to
/// `AtRisk`, a false positive with no true evidence behind it. These tests
/// exercise the fix directly at the repository layer (deterministic, no
/// topology/network involved) rather than only via the much heavier
/// full-daemon integration test.
#[cfg(test)]
mod block_fetch_refusal_tests {
    use super::*;

    /// A minimal schema covering only what these tests touch
    /// (`block_fetch_refusals`) -- `yadorilink_sqlite_runtime::init_schema`
    /// itself assumes a sibling schema-init call already created `changes`/
    /// `pruned_changes` (see that function's own doc comment), which these
    /// tests have no need for. Kept byte-identical to the `CREATE TABLE`
    /// in `yadorilink-sqlite-runtime/src/schema.rs`.
    fn open_test_db() -> Arc<SyncDatabase> {
        Arc::new(
            SyncDatabase::open_in_memory(|conn| {
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS block_fetch_refusals (
                        group_id              TEXT NOT NULL,
                        path                  TEXT NOT NULL,
                        version_hash          TEXT NOT NULL,
                        peer_device_id        TEXT NOT NULL,
                        reason                TEXT NOT NULL,
                        refused_at_unix_nanos INTEGER NOT NULL,
                        PRIMARY KEY (group_id, path, version_hash, peer_device_id)
                    );",
                )
                .map_err(yadorilink_sqlite_runtime::DatabaseError::from)
            })
            .expect("open in-memory db"),
        )
    }

    /// The exact false-positive scenario the reviewer described: a refusal
    /// recorded against V1 must never show up as evidence when the query is
    /// asked about V2, even for the same `(group_id, path, peer_device_id)`.
    #[test]
    fn refusal_recorded_against_one_version_is_invisible_to_a_different_version() {
        let repo = MaterializationStateRepository::new(open_test_db());
        let group_id = "group-1";
        let path = "foo.txt";
        let v1 = "version-hash-v1";
        let v2 = "version-hash-v2";
        let peer = "peer-m";

        repo.record_block_fetch_refusal(
            group_id,
            path,
            v1,
            peer,
            "no verified group provenance for this block",
            1000,
        )
        .unwrap();

        assert_eq!(
            repo.refusing_peers_for_path(group_id, path, v1).unwrap(),
            std::collections::HashSet::from([peer.to_string()]),
            "the refused version must see the refusal"
        );
        assert!(
            repo.refusing_peers_for_path(group_id, path, v2).unwrap().is_empty(),
            "a DIFFERENT version of the same path must never inherit another version's refusal \
             evidence"
        );
    }

    /// A peer that once refused a version but has since successfully
    /// delivered it can never be read as still refusing it -- the stale-
    /// evidence-invalidation half of the fix.
    #[test]
    fn clearing_a_refusal_removes_only_that_exact_peer_path_version_row() {
        let repo = MaterializationStateRepository::new(open_test_db());
        let group_id = "group-1";
        let path = "foo.txt";
        let version = "version-hash-v1";
        let refusing_peer = "peer-m";
        let other_refusing_peer = "peer-w";

        repo.record_block_fetch_refusal(
            group_id,
            path,
            version,
            refusing_peer,
            "no verified group provenance for this block",
            1000,
        )
        .unwrap();
        repo.record_block_fetch_refusal(
            group_id,
            path,
            version,
            other_refusing_peer,
            "no verified group provenance for this block",
            1000,
        )
        .unwrap();
        assert_eq!(
            repo.refusing_peers_for_path(group_id, path, version).unwrap().len(),
            2,
            "both refusals must be visible before either is cleared"
        );

        // `refusing_peer` later successfully delivers the block.
        repo.clear_block_fetch_refusal(group_id, path, version, refusing_peer).unwrap();

        let remaining = repo.refusing_peers_for_path(group_id, path, version).unwrap();
        assert_eq!(
            remaining,
            std::collections::HashSet::from([other_refusing_peer.to_string()]),
            "clearing one peer's refusal must not affect a different peer's still-standing \
             refusal for the same path/version"
        );
    }

    /// Clearing a refusal for one version must never touch a refusal
    /// recorded against a DIFFERENT version of the same path/peer -- the
    /// two rows are independent by construction (different primary keys),
    /// but this pins that invariant explicitly since it is exactly the kind
    /// of thing a future schema change could silently break.
    #[test]
    fn clearing_a_refusal_for_one_version_does_not_affect_a_different_version() {
        let repo = MaterializationStateRepository::new(open_test_db());
        let group_id = "group-1";
        let path = "foo.txt";
        let v1 = "version-hash-v1";
        let v2 = "version-hash-v2";
        let peer = "peer-m";

        repo.record_block_fetch_refusal(
            group_id,
            path,
            v1,
            peer,
            "no verified group provenance for this block",
            1000,
        )
        .unwrap();
        repo.record_block_fetch_refusal(
            group_id,
            path,
            v2,
            peer,
            "no verified group provenance for this block",
            1000,
        )
        .unwrap();

        repo.clear_block_fetch_refusal(group_id, path, v1, peer).unwrap();

        assert!(
            repo.refusing_peers_for_path(group_id, path, v1).unwrap().is_empty(),
            "v1's refusal must be gone"
        );
        assert_eq!(
            repo.refusing_peers_for_path(group_id, path, v2).unwrap(),
            std::collections::HashSet::from([peer.to_string()]),
            "v2's independent refusal must be untouched by clearing v1's"
        );
    }
}

/// `list_held_paths` is the candidate set a hazard re-check sweep walks --
/// nothing today re-evaluates a held path's hazard once the sibling that
/// caused it changes, so this listing is the piece that makes such a sweep
/// possible at all (see the method's own doc comment).
#[cfg(test)]
mod held_state_tests {
    use super::*;

    /// Full schema: DAG tables first (`yadorilink_sqlite_runtime::
    /// init_schema` assumes `changes`/`pruned_changes` already exist, per
    /// its own doc comment), then the real `files` table.
    fn open_full_test_db() -> Arc<SyncDatabase> {
        Arc::new(
            SyncDatabase::open_in_memory(|conn| {
                crate::dag_store::init_dag_schema(conn)
                    .map_err(|e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()))?;
                yadorilink_sqlite_runtime::init_schema(conn)
            })
            .expect("open in-memory db"),
        )
    }

    fn seed_file_row(conn: &rusqlite::Connection, group_id: &str, path: &str) {
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json) \
             VALUES (?1, ?2, 0, 0, '[]')",
            rusqlite::params![group_id, path],
        )
        .unwrap();
    }

    /// Only currently-held paths in the requested group are listed -- an
    /// unheld path, and a held path from a DIFFERENT group, must not leak
    /// in.
    #[test]
    fn lists_only_currently_held_paths_in_the_requested_group() {
        let db = open_full_test_db();
        db.write::<_, SyncSqliteError>(|conn| {
            seed_file_row(conn, "group-1", "held.txt");
            seed_file_row(conn, "group-1", "not-held.txt");
            seed_file_row(conn, "group-2", "held-in-other-group.txt");
            Ok(())
        })
        .unwrap();
        let repo = MaterializationStateRepository::new(db);
        repo.set_held("group-1", "held.txt", "case_collision", 1000).unwrap();
        repo.set_held("group-2", "held-in-other-group.txt", "case_collision", 1000).unwrap();

        assert_eq!(repo.list_held_paths("group-1").unwrap(), vec!["held.txt".to_string()]);
    }

    /// Once a hold is cleared, the path must disappear from the listing --
    /// otherwise a sweep built on this method would keep re-visiting a path
    /// that no longer needs it.
    #[test]
    fn a_cleared_hold_disappears_from_the_listing() {
        let db = open_full_test_db();
        db.write::<_, SyncSqliteError>(|conn| {
            seed_file_row(conn, "group-1", "was-held.txt");
            Ok(())
        })
        .unwrap();
        let repo = MaterializationStateRepository::new(db);
        repo.set_held("group-1", "was-held.txt", "case_collision", 1000).unwrap();
        assert_eq!(repo.list_held_paths("group-1").unwrap(), vec!["was-held.txt".to_string()]);

        repo.clear_held("group-1", "was-held.txt").unwrap();

        assert!(repo.list_held_paths("group-1").unwrap().is_empty());
    }
}
