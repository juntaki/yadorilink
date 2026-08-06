//! `LinkRepository` owns the `links` table (plus `duplicate_recovery_paths`).
//! Some of its methods are read-only lookups that also serve as internal
//! helpers for `yadorilink-sync-core`'s `repository::enrollment::
//! EnrollmentRepository`'s cross-table atomic methods, which write to
//! `links` inside their own transaction -- see that module's doc comment on
//! those methods for why it calls [`LinkRepository::insert_link_row`]
//! directly instead of duplicating it.

use std::sync::Arc;

use rusqlite::OptionalExtension;

use crate::error::SyncSqliteError;
use crate::file_index::enumerate_group_durability_roots_on_conn;
use yadorilink_replica_domain::session_state::{FolderLink, LinkGate, MaterializationPolicy};
use yadorilink_sqlite_runtime::SyncDatabase;

pub struct LinkRepository {
    database: Arc<SyncDatabase>,
}

impl LinkRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// A folder group's materialization policy, by `group_id`
    /// rather than `local_path` — the lookup `PeerSyncSession::materialize`
    /// needs, since it only knows the folder group, not the local path a
    /// caller linked it under. `None` if no link is registered for this
    /// group at all (shouldn't normally happen for a group actively being
    /// synced, but isn't treated as an error here).
    pub fn materialization_policy_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<MaterializationPolicy>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Self::ensure_unambiguous_group_on_conn(conn, group_id, None)?;
            let policy: Option<String> = conn
                .query_row(
                    "SELECT materialization_policy FROM links WHERE group_id = ?1 AND orphaned = 0 \
                     ORDER BY local_path",
                    [group_id],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(policy.as_deref().map(MaterializationPolicy::from_db_str))
        })
    }

    /// The ONLY way a row enters `links`. Both public insert entry points call
    /// this and nothing else, so the one-live-link-per-group invariant cannot be
    /// forgotten at a future third insert site: there is no other function in
    /// this file that names `INSERT INTO links`.
    ///
    /// Takes a `&Transaction`, not a `&Connection`, on purpose: the check and
    /// the write must be one unit under `BEGIN IMMEDIATE`, or two concurrent
    /// `link` calls each read "no existing live link" and both insert. That
    /// atomicity is also why this lives here and not in the daemon's `link`
    /// handler — a check up there cannot be in the same transaction as the
    /// insert down here, so it is a TOCTOU window by construction. The handler's
    /// own check is an ergonomic early refusal, not the invariant.
    ///
    /// `INSERT OR REPLACE` is deliberately NOT used, here or anywhere else on
    /// this table. Measured, it does three separate silent harms: with a UNIQUE
    /// index present it DELETES the conflicting row instead of erroring; it
    /// resets `root_token` to NULL (re-arming adoption, which disarms the
    /// unmounted-volume guard); and it flips `orphaned` 1 → 0, an un-orphan path
    /// nothing in the code intends. A plain `INSERT` lets the primary key refuse
    /// the repoint case, which also makes the SQL and Rust layers agree instead
    /// of diverge.
    ///
    /// `pub`, not `pub(crate)`: `yadorilink-sync-core`'s own
    /// `repository::enrollment::EnrollmentRepository` calls this directly, on
    /// its own already-open transaction, for the exact atomicity reason above
    /// -- see that module's doc comment.
    pub fn insert_link_row(
        tx: &rusqlite::Transaction<'_>,
        local_path: &str,
        group_id: &str,
    ) -> Result<(), SyncSqliteError> {
        // A live row for this group at any OTHER path is THE bug: two roots on
        // one group tombstone each other's files group-wide. Never guess which
        // root is meant — refuse and name both. A live row at THIS path is a
        // re-link, handled below.
        let live = Self::live_link_paths_on_conn(tx, group_id)?;
        if live.iter().any(|p| p != local_path) {
            let mut local_paths = live;
            if !local_paths.iter().any(|p| p == local_path) {
                local_paths.push(local_path.to_string());
            }
            local_paths.sort();
            return Err(SyncSqliteError::AmbiguousLink {
                group_id: group_id.to_string(),
                local_paths,
            });
        }

        let existing_group: Option<String> = tx
            .query_row("SELECT group_id FROM links WHERE local_path = ?1", [local_path], |r| {
                r.get(0)
            })
            .optional()?;
        match existing_group {
            // This path is already registered to a DIFFERENT group. `INSERT OR
            // REPLACE` used to silently repoint the folder while every one of
            // its indexed file rows still belonged to the old group.
            Some(g) if g != group_id => Err(SyncSqliteError::InvalidInput(format!(
                "{local_path} is already linked to folder group {g}; unlink it before linking it \
                 to {group_id}"
            ))),
            // Same path, same group: a deliberate re-link (including the
            // idempotent retry after a failed link's rollback). Un-orphan and
            // un-pause EXPLICITLY, preserving `root_token` and the
            // materialization policy — leaving the row untouched instead would
            // make re-linking an orphaned folder a silent no-op.
            Some(_) => {
                tx.execute(
                    "UPDATE links SET paused = 0, orphaned = 0 WHERE local_path = ?1",
                    [local_path],
                )?;
                Ok(())
            }
            None => {
                tx.execute(
                    "INSERT INTO links (local_path, group_id, paused) VALUES (?1, ?2, 0)",
                    rusqlite::params![local_path, group_id],
                )?;
                Ok(())
            }
        }
    }

    pub fn add_link(&self, local_path: &str, group_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            Self::insert_link_row(tx, local_path, group_id)?;
            Ok(())
        })
    }

    /// Whether this device holds a live (non-orphaned) link for `group_id`.
    /// Scoped to one group rather than reusing `list_links` because this runs
    /// on the peer-apply path, once per change batch.
    ///
    /// Counts rather than `EXISTS`: `EXISTS` reads `true` for one live link and
    /// for two alike, so it cannot see the one state that must not proceed. Two
    /// or more is [`SyncSqliteError::AmbiguousLink`], which the caller
    /// (`SyncState::absent_gate_verdict`) already maps to `StartupFailed` under
    /// its own "an unreadable link table fails closed" rule — the change defers
    /// rather than applying against a root we cannot name.
    pub fn has_live_link_for_group(&self, group_id: &str) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Self::ensure_unambiguous_group_on_conn(conn, group_id, None)?;
            let live: i64 = conn.query_row(
                "SELECT COUNT(*) FROM links WHERE group_id = ?1 AND orphaned = 0",
                [group_id],
                |r| r.get(0),
            )?;
            Ok(live != 0)
        })
    }

    pub fn remove_link(&self, local_path: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute("DELETE FROM links WHERE local_path = ?1", [local_path])?;
            Ok(())
        })
    }

    pub fn list_links(&self) -> Result<Vec<FolderLink>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT local_path, group_id, paused, materialization_policy, \
                 max_local_size_bytes, orphaned FROM links",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(FolderLink {
                    local_path: r.get(0)?,
                    group_id: r.get(1)?,
                    paused: r.get::<_, i64>(2)? != 0,
                    materialization_policy: MaterializationPolicy::from_db_str(
                        &r.get::<_, String>(3)?,
                    ),
                    max_local_size_bytes: r.get(4)?,
                    orphaned: r.get::<_, i64>(5)? != 0,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// This group's sync-root identity nonce, or `None` if the link has not
    /// been adopted yet (it predates the `root_token` column) or no link is
    /// registered for the group at all. See
    /// [`yadorilink_root_authority::root_identity`] for what the token is and
    /// why "not adopted yet" must stay distinguishable from any particular
    /// token value.
    ///
    /// Keyed by `group_id` rather than `local_path`, matching
    /// [`Self::materialization_policy_for_group`] and
    /// [`Self::windows_symlink_opt_in_for_group`] -- the caller
    /// (`VerifiedRoot::open`) knows the group and the root it was handed, not
    /// which row's `local_path` string that root canonicalizes from.
    ///
    /// A group has at most ONE live link. Two or more is
    /// [`SyncSqliteError::AmbiguousLink`] and is refused here rather than
    /// resolved. This comment previously said the opposite — that nothing
    /// forbids two links sharing a `group_id` and that the pair would be
    /// "mutually substitutable". They are not substitutable: the index is
    /// group-scoped and path-relative while every scan is root-scoped and
    /// authoritative, so each root's scan tombstones the other root's files
    /// group-wide, on every device. Sharing a token is what makes the two
    /// indistinguishable, not what makes them safe.
    ///
    /// `orphaned = 0` is load-bearing, not tidying: it makes this read key on
    /// EXACTLY the row set the ambiguity gate one line above counts. Without it
    /// the gate counts LIVE rows while the `SELECT` reads ALL rows and silently
    /// takes the lowest `local_path` — so on the ordinary "1 orphaned + 1 live"
    /// group the DEAD root's token is returned for the LIVE root, and
    /// [`yadorilink_root_authority::root_identity::VerifiedRoot::open`] either
    /// accuses a healthy root of being a restored backup, or (unmarked root,
    /// corroborated evidence) hands that dead token to `adopt_unmarked_root`,
    /// which stamps it into the LIVE root's marker. That last one manufactures
    /// the "two folders sharing one token, permanently indistinguishable" state
    /// this module exists to prevent, on the READ side, where no writer assert
    /// can see it. Pinned by
    /// `the_live_root_does_not_inherit_the_orphaned_roots_token`.
    ///
    /// `None` for an all-orphaned group is correct and does NOT weaken
    /// adoption: `persisted` is not an input to the adopt/refuse decision (see
    /// `adopt_unmarked_root`, which consults on-disk evidence alone and touches
    /// the token strictly AFTER that check has passed), so `None` changes only
    /// WHICH token a legitimate adoption stamps — reuse vs mint — never WHETHER
    /// one happens. Pinned by
    /// `a_token_absent_group_still_refuses_to_adopt_a_bare_root`.
    pub fn link_root_token_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Self::ensure_unambiguous_group_on_conn(conn, group_id, None)?;
            let token = conn
                .query_row(
                    "SELECT root_token FROM links WHERE group_id = ?1 AND orphaned = 0 \
                     ORDER BY local_path",
                    [group_id],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?;
            // Flatten "no link row" and "link row with a NULL token" together:
            // both mean "no adopted identity to check against", and the
            // caller's decision is the same for each.
            Ok(token.flatten())
        })
    }

    /// Records the sync-root identity nonce for a group's link(s).
    ///
    /// Unconditional (it overwrites any existing token) because both callers
    /// need that: adoption only reaches here when the token was absent, and
    /// re-adoption -- the deliberate "this really is a different folder now"
    /// action -- exists precisely to replace it. A group with no link row is not
    /// an error: `SyncState` is used directly, without a link registered, by
    /// tests and by callers that drive a scan against a bare directory, and
    /// there is nothing to persist for them. The marker on disk still carries
    /// the identity in that case.
    ///
    /// The `WHERE` is by `group_id` and so is unqualified by `local_path`: if a
    /// group somehow has two LIVE rows, this stamps the SAME token onto BOTH,
    /// actively manufacturing the "two mutually substitutable roots" state and
    /// making the pair permanently indistinguishable by the very identity check
    /// meant to tell them apart. Asserting on rows-changed turns that fan-out
    /// into a structural detector at the exact site of the damage — no rule for
    /// a future author to remember at a sibling call site. Mirrors
    /// [`Self::mark_link_orphaned`]'s existing rows-changed assert.
    ///
    /// `AND orphaned = 0` is what makes that assert agree with the gate instead
    /// of contradicting it. Without it the gate refuses on >= 2 LIVE rows while
    /// this counts ALL rows, so the ordinary "1 orphaned + 1 live" group — join,
    /// activation never confirmed, link orphaned, user retries the join at a new
    /// folder — is a state the gate calls LEGAL and this writer saw as 2 rows:
    /// `Err(AmbiguousLink)` forever, from `VerifiedRoot::open` AND from
    /// `readopt`, the documented escape hatch (which mints and writes the marker
    /// BEFORE this call, so it could never succeed). The group's sole live root
    /// could never be verified again on that device — permanently unsyncable,
    /// with no attacker and no corruption. Pinned by
    /// `a_group_with_one_orphaned_and_one_live_link_still_verifies_its_live_root`.
    ///
    /// With the filter, `affected > 1` fires on EXACTLY the condition the gate
    /// refuses, which `ensure_single_root` has already rejected at the top of
    /// both constructors — so this goes from contradicting the gate to being
    /// defence-in-depth behind it. `affected == 0` stays `Ok`: the documented
    /// "no link registered / bare-directory scan" case (see
    /// [`Self::ensure_unambiguous_group_on_conn`] on why zero live links is
    /// legal), which an all-orphaned group now also reaches — inert and
    /// idempotent, since the marker holds the identity and re-linking that path
    /// un-orphans the row with its `root_token` preserved.
    pub fn set_link_root_token_for_group(
        &self,
        group_id: &str,
        root_token: &str,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let affected = tx.execute(
                "UPDATE links SET root_token = ?2 WHERE group_id = ?1 AND orphaned = 0",
                rusqlite::params![group_id, root_token],
            )?;
            if affected > 1 {
                // The rows-changed count is only observable AFTER the write,
                // so without the enclosing transaction this would stamp both
                // rows and only then report the problem — deepening the very
                // state it refuses, and leaving the pair indistinguishable
                // exactly as if there had been no check at all. Returning
                // `Err` here means `write_immediate` never commits the
                // transaction, so nothing is stamped.
                //
                // Names the LIVE paths only: every path here is one the user can
                // act on, since the write that failed touched live rows alone.
                // Naming an orphaned row would send the user to `unlink` a
                // folder whose removal changes nothing about this refusal.
                let local_paths = Self::live_link_paths_on_conn(tx, group_id)?;
                return Err(SyncSqliteError::AmbiguousLink {
                    group_id: group_id.to_string(),
                    local_paths,
                });
            }
            Ok(())
        })
    }

    /// Forges the two-live-links-on-one-group state that the whole
    /// one-live-link-per-group fix exists to outlaw, by dropping the schema
    /// triggers and inserting behind the Rust chokepoint's back.
    ///
    /// Test-only, and necessarily so: the write side now refuses to produce this
    /// state, so every test that pins what the READ side does about an
    /// already-duplicated database (the state a user can already be in today,
    /// which is the whole point of the fix) has to manufacture it. One helper
    /// rather than per-test raw SQL, so there is exactly one place that knows
    /// how to bypass the guards.
    ///
    /// Returns `Result` rather than unwrapping internally so this file keeps its
    /// "no panic on an index path" property whole (`check-index-read-fail-closed`
    /// enforces it textually, and rightly does not care that these lines are
    /// cfg-gated). Callers are tests and unwrap at their own call site, where a
    /// failure reads as the test's own setup breaking.
    #[cfg(any(test, feature = "test-support"))]
    pub fn force_second_live_link_for_test(
        &self,
        local_path: &str,
        group_id: &str,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute_batch(
                "DROP TRIGGER links_one_live_root_per_group_insert; \
                 DROP TRIGGER links_one_live_root_per_group_unorphan;",
            )?;
            conn.execute(
                "INSERT INTO links (local_path, group_id, paused) VALUES (?1, ?2, 0)",
                rusqlite::params![local_path, group_id],
            )?;
            Ok(())
        })
    }

    /// Marks a link's coordination-side authorization as permanently gone
    /// (see `FolderLink::orphaned`) -- called only once reconciliation
    /// confirms a `Deleted` activation outcome, meaning there is nothing
    /// left to activate. Never touches the link's on-disk files: this only
    /// flips a local bookkeeping flag so sync stops treating the link as
    /// live.
    pub fn mark_link_orphaned(&self, local_path: &str) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute("UPDATE links SET orphaned = 1 WHERE local_path = ?1", [local_path])?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Sets a folder group's default materialization policy for
    /// newly-adopted files — `yadorilink link --on-demand` or
    /// its Eager-default counterpart.
    pub fn set_materialization_policy(
        &self,
        local_path: &str,
        policy: MaterializationPolicy,
    ) -> Result<(), SyncSqliteError> {
        // `orphaned = 0` keeps an orphaned link out of the mutation target:
        // its authorization is permanently gone, so its storage mode must not
        // be changeable as if it were live. Live reads already exclude it; the
        // write target should be hidden too. A match-less UPDATE surfaces as
        // NotFound, same as an unknown path.
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE links SET materialization_policy = ?1 \
                 WHERE local_path = ?2 AND orphaned = 0",
                rusqlite::params![policy.as_db_str(), local_path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Whether `group_id`'s link has opted in
    /// to attempting real Win32 symlink creation on Windows, rather than
    /// the default skip-with-visible-status policy. Mirrors
    /// `materialization_policy_for_group`'s by-`group_id` lookup shape —
    /// `PeerSyncSession::materialize` only knows the folder group, not the
    /// local path a caller linked it under. `false` (not an error) if no
    /// link is registered for this group at all, matching the "default
    /// policy" this column's own `DEFAULT 0` already implies.
    ///
    /// `orphaned = 0` for the same reason as every other by-`group_id`
    /// resolver, and this site is why "mirrors `materialization_policy_for_group`"
    /// was not enough: that function IS orphan-filtered and this one was not, so
    /// the claim to mirror it was already false. Unfiltered, the gate counts
    /// LIVE rows while the `SELECT` reads ALL of them and takes the lowest
    /// `local_path` — so on a "1 orphaned + 1 live" group with the orphaned path
    /// sorting first, the LIVE folder is materialized under the DEAD folder's
    /// symlink policy. Pinned by
    /// `an_orphaned_rows_symlink_opt_in_does_not_decide_the_live_links_policy`.
    pub fn windows_symlink_opt_in_for_group(
        &self,
        group_id: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Self::ensure_unambiguous_group_on_conn(conn, group_id, None)?;
            let opt_in: Option<i64> = conn
                .query_row(
                    "SELECT windows_symlink_opt_in FROM links \
                     WHERE group_id = ?1 AND orphaned = 0 ORDER BY local_path",
                    [group_id],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(opt_in.unwrap_or(0) != 0)
        })
    }

    /// Sets a folder link's per-link opt-in for attempting real Windows
    /// symlink materialization — mirrors
    /// `set_materialization_policy`'s by-`local_path` shape (every other
    /// per-link setting here is addressed by local path, the same surface
    /// a future CLI flag, section 6, would use). Device-local, like every
    /// other policy column on `links`.
    pub fn set_windows_symlink_opt_in(
        &self,
        local_path: &str,
        opt_in: bool,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE links SET windows_symlink_opt_in = ?1 WHERE local_path = ?2",
                rusqlite::params![opt_in as i64, local_path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Sets (or clears, with `None`) an `OnDemand` folder's automatic
    /// eviction disk-usage cap — unset means no automatic
    /// eviction, matching the existing manual-only default.
    pub fn set_max_local_size_bytes(
        &self,
        local_path: &str,
        max_bytes: Option<i64>,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE links SET max_local_size_bytes = ?1 WHERE local_path = ?2",
                rusqlite::params![max_bytes, local_path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    pub fn set_paused(&self, local_path: &str, paused: bool) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE links SET paused = ?1 WHERE local_path = ?2",
                rusqlite::params![paused as i64, local_path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Whether `group_id`'s next full scan must be additive — indexing what it
    /// finds but emitting no deletions.
    ///
    /// Set when a group is recovered out of the two-live-roots state by
    /// unlinking one of its folders. See the column's own comment in `init` for
    /// why the ordinary remedy is otherwise destructive.
    ///
    /// Reads the flag for the group's single live link. Ambiguity is refused
    /// (rather than defaulting to `false`) for the same reason as every other
    /// by-`group_id` resolver: `false` here means "deletions are safe to emit",
    /// which is precisely the answer that must never be guessed.
    pub fn suppress_tombstones_for_group(&self, group_id: &str) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Self::ensure_unambiguous_group_on_conn(conn, group_id, None)?;
            let flag: Option<i64> = conn
                .query_row(
                    "SELECT suppress_tombstones_until_scan FROM links \
                     WHERE group_id = ?1 AND orphaned = 0 ORDER BY local_path",
                    [group_id],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(flag.unwrap_or(0) != 0)
        })
    }

    /// Arms the additive-scan flag on `local_path`'s link.
    pub fn set_suppress_tombstones(
        &self,
        local_path: &str,
        suppress: bool,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE links SET suppress_tombstones_until_scan = ?1 WHERE local_path = ?2",
                rusqlite::params![suppress as i64, local_path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Durably records the exact live paths whose presence must be recovered
    /// after removing a duplicate root. Re-arming is idempotent.
    pub fn arm_duplicate_recovery_paths(&self, group_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO duplicate_recovery_paths (group_id, path) \
                 SELECT group_id, path FROM files \
                 WHERE group_id = ?1 AND state = 'current' AND deleted = 0",
                [group_id],
            )?;
            Ok(())
        })
    }

    pub fn resolve_duplicate_recovery_path(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM duplicate_recovery_paths WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
            )?;
            Ok(())
        })
    }

    pub fn duplicate_recovery_pending(&self, group_id: &str) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM duplicate_recovery_paths WHERE group_id = ?1)",
                [group_id],
                |row| row.get(0),
            )?)
        })
    }

    /// Every live (`orphaned = 0`) `local_path` registered for `group_id`,
    /// ordered by path.
    ///
    /// `ORDER BY` is not cosmetic. Every by-`group_id` resolver in this file
    /// used to be an unordered `query_row`, i.e. a silent first-row-wins over a
    /// set SQLite is free to return in any order — half of what made two links
    /// on one group a *silent* fault instead of a loud one. A stable order also
    /// keeps [`SyncSqliteError::AmbiguousLink`]'s message stable between runs,
    /// which is what makes it a usable instruction.
    fn live_link_paths_on_conn(
        conn: &rusqlite::Connection,
        group_id: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        let mut stmt = conn.prepare(
            "SELECT local_path FROM links WHERE group_id = ?1 AND orphaned = 0 ORDER BY local_path",
        )?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Refuses `group_id` if it has more than one live link, optionally ignoring
    /// the row at `excluding` (the caller's own path, for a same-path re-link).
    ///
    /// `> 1`, never `!= 1`: zero live links is legal and load-bearing — it is
    /// the documented "no link registered, drive a scan against a bare
    /// directory" case (see [`Self::set_link_root_token_for_group`]), which
    /// tests and direct `SyncState` users rely on. Refusing zero here would
    /// break them for no safety gain: with no link there is no second root to
    /// confuse this one with.
    ///
    /// Free function over `&Connection` rather than a method so the write
    /// chokepoint can run it *inside* its open transaction — the check and the
    /// insert must be one unit, or two concurrent `link` calls both pass it.
    pub(crate) fn ensure_unambiguous_group_on_conn(
        conn: &rusqlite::Connection,
        group_id: &str,
        excluding: Option<&str>,
    ) -> Result<(), SyncSqliteError> {
        let paths: Vec<String> = Self::live_link_paths_on_conn(conn, group_id)?
            .into_iter()
            .filter(|p| Some(p.as_str()) != excluding)
            .collect();
        if paths.len() > 1 {
            return Err(SyncSqliteError::AmbiguousLink {
                group_id: group_id.to_string(),
                local_paths: paths,
            });
        }
        Ok(())
    }

    /// Pooled wrapper over [`Self::ensure_unambiguous_group_on_conn`] — the
    /// read-side seam callers outside this module use to refuse an ambiguous
    /// group before doing anything else.
    pub fn ensure_unambiguous_group(&self, group_id: &str) -> Result<(), SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Self::ensure_unambiguous_group_on_conn(conn, group_id, None)
        })
    }

    /// Every live `local_path` for `group_id`, refusing the ambiguous case.
    /// The `Vec` is empty or one element; anything else is
    /// [`SyncSqliteError::AmbiguousLink`].
    pub fn live_link_paths_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| Self::live_link_paths_on_conn(conn, group_id))
    }

    /// The one live `local_path` for `group_id`, or `None` if the group has no
    /// live link. Refuses (rather than guessing) when two or more share the
    /// group — the resolver every by-`group_id` root lookup outside this module
    /// funnels through.
    pub fn live_link_local_path_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Self::ensure_unambiguous_group_on_conn(conn, group_id, None)?;
            Ok(Self::live_link_paths_on_conn(conn, group_id)?.into_iter().next())
        })
    }

    /// The single link-table gate the peer-apply path consults before writing
    /// anything for `group_id` — "may this device apply a peer change to this
    /// group, and if so, where and how eagerly?" — in one lookup.
    ///
    /// This exists because that question used to be answered by three
    /// independent by-`group_id` lookups (`paused`, the materialization
    /// policy, and the session's own construction-time root snapshot), each of
    /// which resolved a *missing* link row permissively and on its own: a
    /// deleted row read as "not paused", as "no policy → default Eager", and
    /// left the session's frozen root untouched. Unlinking a folder deletes
    /// exactly that row, so each lookup independently waved through applies
    /// into a folder the user had detached — including the `remove_file` of a
    /// tombstone, against an explicit "your local files are not deleted"
    /// promise. Any single one failing open is sufficient for the loss, so the
    /// gate has to be *one* seam that cannot be defaulted past, not three
    /// hardened lookups.
    ///
    /// Called once per change batch — the same granularity
    /// `has_live_link_for_group` already uses, and cheap at that rate (one
    /// indexed lookup on a table with one row per linked folder).
    ///
    /// `orphaned = 0` is part of the gate, not an afterthought: an orphaned
    /// link's on-disk files are documented as never touched or deleted (see
    /// `FolderLink::orphaned`), which the old `paused` lookup did not honour
    /// — it read an orphaned row's `paused = 0` as "not paused" and let the
    /// apply proceed, contradicting the column's own contract.
    ///
    /// Two or more live links is `Err(AmbiguousLink)`, deliberately *not* a new
    /// `LinkGate::Ambiguous` variant: three of this enum's five consumers match
    /// with `matches!`/let-else, so a new variant would compile clean at every
    /// one of them and silently read as "not Live" — the exact fail-open shape
    /// this gate exists to prevent. `?` on a `Result` propagates loudly at all
    /// five instead.
    pub fn link_gate_for_group(&self, group_id: &str) -> Result<LinkGate, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Self::ensure_unambiguous_group_on_conn(conn, group_id, None)?;
            let row: Option<(String, i64, String)> = conn
                .query_row(
                    "SELECT local_path, paused, materialization_policy FROM links \
                     WHERE group_id = ?1 AND orphaned = 0 ORDER BY local_path",
                    [group_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((local_path, paused, policy)) = row else {
                return Ok(LinkGate::NoLiveLink);
            };
            if paused != 0 {
                return Ok(LinkGate::Paused { local_path });
            }
            Ok(LinkGate::Live { local_path, policy: MaterializationPolicy::from_db_str(&policy) })
        })
    }

    /// Whether `group_id`'s link is currently paused, by `group_id`. Pause
    /// stops both directions.
    ///
    /// NOT a safety gate on its own, and must not be used as one: `false`
    /// covers both "a live link that is not paused" and "no live link at all",
    /// so a caller that only checks this admits writes for an unlinked group.
    /// A caller deciding whether it may touch the filesystem wants
    /// [`Self::link_gate_for_group`], which distinguishes the two. This
    /// remains only for callers asking the narrow, genuinely boolean question
    /// "has the user paused this link?".
    pub fn is_paused_for_group(&self, group_id: &str) -> Result<bool, SyncSqliteError> {
        Ok(matches!(self.link_gate_for_group(group_id)?, LinkGate::Paused { .. }))
    }

    /// Atomically re-confirms `expected_digest` against `group_id`'s CURRENT
    /// durability-root set and, only if it still matches, flips `local_path`'s
    /// materialization policy to `policy` — both inside a single write
    /// transaction, so no concurrent index write (a watcher-driven local edit)
    /// can land between the re-check and the commit. This is the atomic
    /// counterpart to reading a digest, comparing it, and writing separately:
    /// there the tiny window between the read and the write could admit an
    /// interleaved `files` change that the just-confirmed peer never covered.
    ///
    /// Returns `Ok(true)` if the digest still matched and the policy was
    /// committed, `Ok(false)` if the digest no longer matches (the set moved
    /// after the peer confirmation; nothing is written — fail closed). `Err`
    /// only for a genuine storage error.
    ///
    /// This protects the coordination-plane ROLE flip (eager -> on-demand)
    /// from racing a durability-set change. It is NOT what protects actual
    /// block deletion: reclaiming a specific version's blocks stays
    /// separately gated, per file, by the on-demand eviction custody check
    /// (`confirm_version_present_via_peer` / `holds_version_durably` with
    /// `for_handoff = false`), which is the real backstop against dropping the
    /// last copy of any one version.
    pub fn recheck_digest_then_set_materialization_policy(
        &self,
        group_id: &str,
        local_path: &str,
        policy: MaterializationPolicy,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncSqliteError> {
        // IMMEDIATE takes SQLite's write lock at BEGIN, so the digest
        // re-enumeration below and the policy UPDATE observe one snapshot
        // that no other connection's `files` write can mutate until this
        // transaction commits — the atomicity the separate read-then-write
        // path lacked.
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let current = enumerate_group_durability_roots_on_conn(tx, group_id)?;
            if current.digest != expected_digest {
                // Set moved since the peer confirmation; commit nothing.
                return Ok(false);
            }
            // `orphaned = 0`: an orphaned link's authorization is permanently
            // gone, so its storage-mode role must not be flippable as if live,
            // even on this digest-guarded path.
            let affected = tx.execute(
                "UPDATE links SET materialization_policy = ?1 \
                 WHERE local_path = ?2 AND orphaned = 0",
                rusqlite::params![policy.as_db_str(), local_path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("link {local_path}")));
            }
            Ok(true)
        })
    }

    /// Atomically re-confirms `expected_digest` against `group_id`'s CURRENT
    /// durability-root set and, only if it still matches, removes `local_path`'s
    /// link row — both inside one write transaction, so no concurrent index
    /// write can interleave between the re-check and the removal. See
    /// [`Self::recheck_digest_then_set_materialization_policy`] for the full
    /// rationale (this is the unlink counterpart of the demote commit) and the
    /// same "protects the role flip, not block deletion" caveat.
    ///
    /// Returns `Ok(true)` if the digest still matched and the link was removed,
    /// `Ok(false)` if the digest no longer matches (nothing removed — fail
    /// closed). A `local_path` with no link row that nonetheless passes the
    /// digest check returns `Ok(true)` (removing an absent row is a no-op),
    /// matching [`Self::remove_link`]'s own idempotent delete.
    pub fn recheck_digest_then_remove_link(
        &self,
        group_id: &str,
        local_path: &str,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let current = enumerate_group_durability_roots_on_conn(tx, group_id)?;
            if current.digest != expected_digest {
                return Ok(false);
            }
            tx.execute("DELETE FROM links WHERE local_path = ?1", [local_path])?;
            Ok(true)
        })
    }

    /// Test-only escape hatch: stamps `root_token` directly onto the row at
    /// `local_path`, bypassing every write-side guard (ambiguity refusal,
    /// `INSERT OR REPLACE` avoidance). The writer now refuses to stamp two
    /// live rows, so the "two rows sharing one token" state — which the
    /// PRE-FIX writer manufactured on any database that already had two
    /// links, and which is the state where the read-side gate is the ONLY
    /// remaining protection — can no longer be produced through the public
    /// API. A test that pins the gate has to build it directly. Keyed by
    /// `local_path` precisely so a test can put a DIFFERENT token on each row
    /// when that is what it means.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_link_root_token_for_path_for_test(
        &self,
        local_path: &str,
        root_token: &str,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE links SET root_token = ?2 WHERE local_path = ?1",
                rusqlite::params![local_path, root_token],
            )?)
        })?;
        if affected != 1 {
            return Err(SyncSqliteError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Every row's `root_token` for `group_id`, ordered by `local_path`, with NO
    /// ambiguity check — the raw view a test needs to assert that a refusal
    /// stamped nothing. Production code must never resolve a token this way;
    /// that is what [`Self::link_root_token_for_group`] is for.
    #[cfg(any(test, feature = "test-support"))]
    pub fn link_root_tokens_for_group_unchecked_for_test(
        &self,
        group_id: &str,
    ) -> Result<Vec<Option<String>>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn
                .prepare("SELECT root_token FROM links WHERE group_id = ?1 ORDER BY local_path")?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, Option<String>>(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }
}
