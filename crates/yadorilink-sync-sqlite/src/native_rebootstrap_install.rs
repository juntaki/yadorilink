//! Quarantining and installing: from the preserved barrier to an installed target.
//!
//! It starts from [`Preserved`](crate::native_rebootstrap::RebootstrapState)
//! and takes its input only from the recovery area of the journal's recovery id:
//! the target is the exact bundle stored there, verified again locally from what
//! is stored with it, never an argument and never a bundle fetched again.
//!
//! The group has been frozen since the final capture pass began (see
//! [`crate::native_rebootstrap::group_frozen`]): nothing is authored, admitted or
//! materialized, so the barrier's protected set cannot change under the install.
//!
//! 1. In the transaction that finds that set still identical to what the barrier
//!    recorded (the frontier hash), the journal moves to `Quarantining`. Nothing in
//!    the sync root has been touched yet.
//! 2. The originals of the changes this device may no longer author (a Viewer, a
//!    revoked Writer, a withheld path) leave the root, each only after its
//!    verified copy is in the recovery area, and exactly once. A user's edit made
//!    after the barrier goes into the area first, under its own digest.
//! 3. One transaction replaces the group's native state by the target's, through
//!    [`install_checkpoint`](crate::native_checkpoint_install::install_checkpoint), the
//!    only place a group's state is cleared: it re-checks the barrier immediately
//!    before the clear, installs the target, arms the projection, rotates this
//!    device to a new incarnation and closes the old ones at the target's position
//!    with closures this device signs; this transaction then moves the journal to
//!    `CatchingUp`. A crash before the commit leaves the old state; after it, the new
//!    one. The journal and the closures survive the clear (see
//!    [`CLEARED_BY_INSTALL`](crate::native_checkpoint_install::CLEARED_BY_INSTALL)). What
//!    follows is [`crate::native_rebootstrap_replay`]: the bounded catch-up, the replay of
//!    own intent, and [`crate::native_rebootstrap::finish_rebootstrap`], which ends the
//!    freeze.
//!
//! The materializer is not asked to do anything here: the installed projection is
//! followed through the ordinary scheduler once the freeze ends.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::ids::{FolderGroupId, VersionHash};

use crate::error::SyncSqliteError;
use crate::native_checkpoint_install::{CheckpointError, InstallKind, RebootstrapBarrier};
use crate::native_rebootstrap::{
    area_failure, frozen_frontier_unchanged, rebootstrap_status, resume_preserved, set_state,
    verify_target_in_area, BlockedReason, CaptureBarrier, Crash, InstallAuthority,
    PreservationFailure, PreserveContext, ReassertAuthority, RebootstrapState,
};
use crate::native_rebootstrap_recovery::{sha256, Manifest, RecoveryArea};
use crate::native_rebootstrap_replay::units_replayable_now;
use crate::native_recovery_items::verify_items;

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- The originals of changes this device may no longer author, and what
        -- became of each: progress bookkeeping and the user's pointer to the copy
        -- in the recovery area (the manifest names the versions).
        CREATE TABLE IF NOT EXISTS native_rebootstrap_quarantine (
            group_id    TEXT NOT NULL,
            recovery_id TEXT NOT NULL,
            path        TEXT NOT NULL,
            status      TEXT NOT NULL,
            -- The digest of an edit made after the barrier, kept under `late/`.
            -- Written before the original is removed, so that a crash after the
            -- removal still finds the copy referenced.
            late_sha256 BLOB,
            PRIMARY KEY (group_id, recovery_id, path)
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

// --- the root, as the quarantine sees it ---------------------------------------------------------

/// What stands at a path of the sync root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observed {
    Absent,
    File {
        size: u64,
        sha256: [u8; 32],
    },
    Symlink {
        target: Vec<u8>,
    },
    /// A directory is never the quarantine's to remove: its entries are other
    /// paths.
    Directory,
    Other,
}

/// The sync root, reached by the daemon through its root-confined operations.
pub trait QuarantineRoot {
    fn observe(&self, path: &str) -> Result<Observed, String>;
    /// The bytes of the regular file at `path`.
    fn read_file(&self, path: &str) -> Result<Vec<u8>, String>;
    /// Removes the object at `path` if it is still exactly `expected`.
    ///
    /// Comparing and then unlinking by name is not atomic: the user can save in
    /// between, and the save would be unlinked unseen. A real implementation
    /// therefore renames the object to a private name INSIDE the root (same
    /// volume, so the rename is atomic and the object cannot be written under its
    /// old name any more), verifies the renamed object against `expected`, and
    /// only then unlinks it. If it is not `expected` any more it renames it back
    /// (unless the name was taken again meanwhile, in which case it keeps the
    /// renamed object in the recovery area as a late edit) and returns an error,
    /// so the next attempt observes the new content and saves it first.
    fn remove(&self, path: &str, expected: &Observed) -> Result<(), String>;
}

pub struct InstallContext<'a> {
    pub preserve: &'a PreserveContext<'a>,
    pub root: &'a dyn QuarantineRoot,
    /// The signing key of this device, when it may close its own old
    /// incarnations. Without it (a replica that holds no write authority) the
    /// install signs no closure.
    pub closure_key: Option<&'a ed25519_dalek::SigningKey>,
}

// --- failpoints and results ------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallStep {
    /// Inside the install transaction, after the old native state was deleted.
    NativeStateCleared,
    /// ... after the target was installed through the join.
    TargetInstalled,
    /// ... after the projection was armed for the paths that changed.
    ProjectionArmed,
    /// ... after the incarnation was rotated and the old one closed.
    Rotated,
    /// ... after the journal says `catching_up`.
    Recorded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallPoint {
    /// The journal says `Quarantining`; no original has left the root.
    AfterBeginQuarantine,
    /// The quarantine of the item with this index is complete.
    AfterQuarantineItem(usize),
    InTransaction(InstallStep),
    /// The original with this index has left the root; its record is not yet written.
    AfterOriginalRemoved(usize),
    /// The install is committed.
    AfterCommit,
}

#[derive(Debug)]
pub enum InstallError {
    /// No such rebootstrap, or it is not at a stage the install runs from.
    NotInstallable(String),
    Blocked(BlockedReason),
    /// The stored target was refused by the join.
    BundleRefused(String),
    Crashed,
    /// Another call holds this group's rebootstrap.
    Busy,
    /// What the barrier protected is not what it recorded: the frontier, the closure
    /// rows, the manifest or the capture result moved while the group was frozen, so
    /// something wrote past the freeze. Found before anything was cleared; nothing was.
    FrontierChanged,
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for InstallError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

impl From<CheckpointError> for InstallError {
    fn from(error: CheckpointError) -> Self {
        match error {
            CheckpointError::NotEmpty => {
                Self::NotInstallable("a rebootstrap install met a fresh-install refusal".into())
            }
            CheckpointError::NotInstallable(why) => Self::NotInstallable(why),
            CheckpointError::FrontierChanged => Self::FrontierChanged,
            CheckpointError::Blocked(reason) => Self::Blocked(reason),
            CheckpointError::Crashed => Self::Crashed,
            CheckpointError::Store(error) => Self::Store(error),
            refusal @ (CheckpointError::RetiredAuthorLifted { .. }
            | CheckpointError::ClosureFork { .. }
            | CheckpointError::ClosureNotBound { .. }) => Self::BundleRefused(refusal.to_string()),
        }
    }
}

impl From<rusqlite::Error> for InstallError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}

/// What the install did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    pub recovery_id: String,
    /// The incarnation this device authors as from now on.
    pub new_author: AuthorId,
    /// The incarnations whose uncovered changes were preserved, now closed.
    pub old_authors: Vec<AuthorId>,
}

// --- the entry --------------------------------------------------------------------------------------

/// Installs the target of rebootstrap `recovery_id` of `group`, from the
/// preserved barrier. Idempotent and resumable: called again after a crash it
/// continues from the journal, and once installed it returns the same answer.
pub fn install_rebootstrap(
    conn: &Connection,
    ctx: &InstallContext<'_>,
    group: &FolderGroupId,
    recovery_id: &str,
    hook: &mut dyn FnMut(InstallPoint) -> Result<(), Crash>,
) -> Result<Installed, InstallError> {
    let status = rebootstrap_status(conn, group)?
        .ok_or_else(|| InstallError::NotInstallable("no rebootstrap".into()))?;
    if status.recovery_id != recovery_id {
        return Err(InstallError::NotInstallable(format!(
            "the rebootstrap of {group:?} is {}, not {recovery_id}",
            status.recovery_id
        )));
    }
    if !(matches!(status.state, RebootstrapState::Preserved | RebootstrapState::Quarantining)
        || status.state.is_installed())
    {
        return Err(InstallError::NotInstallable(format!("it is {:?}", status.state)));
    }
    let _busy = match crate::native_rebootstrap::acquire(conn, group) {
        Ok(guard) => guard,
        Err(crate::native_rebootstrap::BusyOrStore::Busy) => return Err(InstallError::Busy),
        Err(crate::native_rebootstrap::BusyOrStore::Store(error)) => {
            return Err(InstallError::Store(error))
        }
    };
    // The target is the stored one, anchored to the journal and verified again
    // from what is stored with it: no peer, no authority, no live policy.
    let preserved =
        resume_preserved(conn, ctx.preserve.recovery_root, group).map_err(InstallError::Blocked)?;
    let area = RecoveryArea::open_dir(&preserved.dir).map_err(|e| blocked_by(area_failure(e)))?;
    let intent = area.read_intent().map_err(|e| blocked_by(area_failure(e)))?;
    let manifest = intent.manifest;

    if status.state.is_installed() {
        return installed_summary(conn, recovery_id, &manifest);
    }

    if status.state == RebootstrapState::Preserved {
        if let CaptureBarrier::Partial { detail } = &ctx.preserve.capture {
            return Err(InstallError::Blocked(BlockedReason::PreservationFailed(
                PreservationFailure::CapturePartial { detail: detail.clone() },
            )));
        }
        verify_target_in_area(&area, group).map_err(|e| {
            InstallError::Blocked(BlockedReason::PreservationFailed(
                PreservationFailure::TargetNotVerifiable { detail: e.to_string() },
            ))
        })?;
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        // The stage is read again inside the write transaction: it may have moved
        // since the first read.
        let still = rebootstrap_status(&tx, group)?;
        if still.as_ref().map(|s| (&s.state, &s.recovery_id))
            != Some((&RebootstrapState::Preserved, &recovery_id.to_owned()))
        {
            return Err(InstallError::NotInstallable("the stage moved".into()));
        }
        if !frozen_frontier_unchanged(&tx, group, &preserved.manifest_sha256)? {
            return Err(InstallError::FrontierChanged);
        }
        verify_items(&tx, &ctx.preserve.items_root, group, &manifest.remote_only)
            .map_err(InstallError::Blocked)?;
        begin_quarantine(
            &tx,
            group,
            recovery_id,
            &manifest,
            ctx.preserve.authority,
            ctx.preserve.now_unix,
        )?;
        tx.commit()?;
    }
    hook(InstallPoint::AfterBeginQuarantine).map_err(|_| InstallError::Crashed)?;

    quarantine(conn, ctx, group, recovery_id, &area, &manifest, hook)?;

    install_in_tx(conn, ctx, group, &area, recovery_id, &manifest, &preserved.manifest_sha256, hook)
}

fn blocked_by(reason: BlockedReason) -> InstallError {
    InstallError::Blocked(reason)
}

// --- beginning the quarantine -------------------------------------------------------------------------------

/// The paths a manifest's changes touch, each marked re-assertable if any change
/// to it is, as the authority answers now.
fn protected_paths(manifest: &Manifest, replayable: &[bool]) -> BTreeMap<String, bool> {
    let mut paths: BTreeMap<String, bool> = BTreeMap::new();
    for item in &manifest.items {
        let entry = paths.entry(item.path.clone()).or_insert(false);
        *entry |= replayable[item.unit];
    }
    paths
}

fn begin_quarantine(
    tx: &Connection,
    group: &FolderGroupId,
    recovery_id: &str,
    manifest: &Manifest,
    authority: &dyn ReassertAuthority,
    now: i64,
) -> Result<(), SyncSqliteError> {
    // The authority is asked again here, immediately before the install: a device that was a
    // Writer when the plan was made and is not now keeps nothing of its intent in the root, it
    // is quarantined. A path is quarantined only if every change to it is one that may not be
    // re-authored: a re-assertable change keeps the file where it is.
    let replayable = units_replayable_now(manifest, authority);
    for (path, reassertable) in &protected_paths(manifest, &replayable) {
        let puts = manifest
            .items
            .iter()
            .any(|item| item.path == *path && !replayable[item.unit] && item.put_version.is_some());
        if !reassertable && puts {
            tx.execute(
                "INSERT OR IGNORE INTO native_rebootstrap_quarantine \
                 (group_id, recovery_id, path, status) VALUES (?1, ?2, ?3, 'pending')",
                (group.as_str(), recovery_id, path),
            )?;
        }
    }
    set_state(tx, group, "quarantining", now)
}

// --- quarantine --------------------------------------------------------------------------------------------

/// What became of a quarantined original.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuarantineStatus {
    /// Not yet looked at.
    Pending,
    /// The original left the root; its verified copy is in the recovery area.
    Removed,
    /// The original left the root, but it was an edit made after the barrier: it
    /// was copied into the area under its own digest first.
    RemovedLateEdit { sha256: [u8; 32] },
    /// Nothing was there to remove (already gone); the copy is in the area.
    AlreadyAbsent,
    /// A directory stands there: not the quarantine's to remove.
    LeftInPlace,
}

/// A change this device can no longer author, kept in the recovery area instead
/// of the sync root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedItem {
    pub recovery_id: String,
    pub path: String,
    pub status: QuarantineStatus,
    /// The versions of this path the area holds, as the manifest names them.
    pub versions: Vec<VersionHash>,
}

fn status_text(status: &QuarantineStatus) -> (&'static str, Option<Vec<u8>>) {
    match status {
        QuarantineStatus::Pending => ("pending", None),
        QuarantineStatus::Removed => ("removed", None),
        QuarantineStatus::RemovedLateEdit { sha256 } => {
            ("removed_late_edit", Some(sha256.to_vec()))
        }
        QuarantineStatus::AlreadyAbsent => ("already_absent", None),
        QuarantineStatus::LeftInPlace => ("left_in_place", None),
    }
}

/// The quarantined items of `group`'s rebootstrap, for the user's status: the
/// recovery id, the relative path and the versions the recovery area holds for it
/// (the manifest at `<recovery id>/manifest.json` names each).
pub fn quarantined_items(
    conn: &Connection,
    group: &FolderGroupId,
    manifest: Option<&Manifest>,
) -> Result<Vec<QuarantinedItem>, SyncSqliteError> {
    let Some(status) = rebootstrap_status(conn, group)? else { return Ok(Vec::new()) };
    let mut stmt = conn.prepare(
        "SELECT path, status, late_sha256 FROM native_rebootstrap_quarantine \
         WHERE group_id = ?1 AND recovery_id = ?2 ORDER BY path ASC",
    )?;
    let rows = stmt
        .query_map((group.as_str(), &status.recovery_id), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(path, state, late)| {
            let corrupt = |what: &str| {
                SyncSqliteError::CorruptState(format!("rebootstrap quarantine {path}: {what}"))
            };
            let status_value = match state.as_str() {
                "pending" | "removing" => QuarantineStatus::Pending,
                "removed" => QuarantineStatus::Removed,
                "removed_late_edit" => {
                    let late = late.ok_or_else(|| corrupt("a late edit without its digest"))?;
                    QuarantineStatus::RemovedLateEdit {
                        sha256: <[u8; 32]>::try_from(late.as_slice())
                            .map_err(|_| corrupt("a digest that is not 32 bytes"))?,
                    }
                }
                "already_absent" => QuarantineStatus::AlreadyAbsent,
                "left_in_place" => QuarantineStatus::LeftInPlace,
                _ => return Err(corrupt("an unknown status")),
            };
            let versions = manifest
                .map(|manifest| quarantined_versions(manifest, &path).into_iter().collect())
                .unwrap_or_default();
            Ok(QuarantinedItem {
                recovery_id: status.recovery_id.clone(),
                path,
                status: status_value,
                versions,
            })
        })
        .collect()
}

/// The versions the preserved changes put at `path`: whichever of them stands in the root is
/// a copy the recovery area already holds, so the unit that is not replayed loses none.
fn quarantined_versions(manifest: &Manifest, path: &str) -> BTreeSet<VersionHash> {
    manifest
        .items
        .iter()
        .filter(|item| item.path == path)
        .filter_map(|item| item.put_version)
        .collect()
}

fn quarantine(
    conn: &Connection,
    ctx: &InstallContext<'_>,
    group: &FolderGroupId,
    recovery_id: &str,
    area: &RecoveryArea,
    manifest: &Manifest,
    hook: &mut dyn FnMut(InstallPoint) -> Result<(), Crash>,
) -> Result<(), InstallError> {
    // `removing` is an original whose copy is referenced and whose removal may or
    // may not have happened: the resume looks again.
    let pending: Vec<(String, Option<[u8; 32]>)> = {
        let mut stmt = conn.prepare(
            "SELECT path, late_sha256 FROM native_rebootstrap_quarantine \
             WHERE group_id = ?1 AND recovery_id = ?2 AND status IN ('pending', 'removing') \
             ORDER BY path ASC",
        )?;
        let rows = stmt
            .query_map((group.as_str(), recovery_id), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(path, late)| {
                let digest = late
                    .map(|bytes| {
                        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                            SyncSqliteError::CorruptState(
                                "a late edit digest is not 32 bytes".into(),
                            )
                        })
                    })
                    .transpose()?;
                Ok::<_, SyncSqliteError>((path, digest))
            })
            .collect::<Result<_, _>>()?
    };
    let failed = |detail: String| {
        InstallError::Blocked(BlockedReason::PreservationFailed(PreservationFailure::Io { detail }))
    };
    // Written before the original leaves, so that nothing that happens after the
    // removal can leave the copy unreferenced.
    let reference = |path: &str, digest: &[u8; 32]| -> Result<(), InstallError> {
        conn.execute(
            "UPDATE native_rebootstrap_quarantine SET status = 'removing', late_sha256 = ?4 \
             WHERE group_id = ?1 AND recovery_id = ?2 AND path = ?3",
            (group.as_str(), recovery_id, path, digest.as_slice()),
        )?;
        Ok(())
    };
    for (index, (path, recorded)) in pending.iter().enumerate() {
        let versions: Vec<&crate::native_rebootstrap_recovery::ManifestVersion> =
            quarantined_versions(manifest, path)
                .into_iter()
                .filter_map(|v| manifest.versions.iter().find(|m| m.version == v))
                .collect();
        // Every copy the original could be is read back before anything is removed.
        for version in versions.iter().filter(|v| v.has_bytes) {
            let bytes =
                area.read_version(&version.version).map_err(|e| blocked_by(area_failure(e)))?;
            if sha256(&bytes) != version.sha256 {
                return Err(blocked_by(BlockedReason::PreservationFailed(
                    PreservationFailure::CopyVerification { item: format!("versions/{path}") },
                )));
            }
        }
        let observed = ctx.root.observe(path).map_err(failed)?;
        let status = match &observed {
            Observed::Absent => match recorded {
                // The removal happened and its record did not.
                Some(digest) => {
                    keep_late_edit_present(area, digest)?;
                    QuarantineStatus::RemovedLateEdit { sha256: *digest }
                }
                None => QuarantineStatus::AlreadyAbsent,
            },
            Observed::Directory | Observed::Other => QuarantineStatus::LeftInPlace,
            Observed::File { sha256: digest, .. } => {
                if recorded.is_none() && versions.iter().any(|v| v.has_bytes && v.sha256 == *digest)
                {
                    ctx.root.remove(path, &observed).map_err(failed)?;
                    QuarantineStatus::Removed
                } else {
                    // An edit nobody has captured: it goes into the area, and is
                    // referenced, before the original leaves.
                    let bytes = ctx.root.read_file(path).map_err(failed)?;
                    if sha256(&bytes) != *digest {
                        return Err(failed(format!("{path} changed while it was being read")));
                    }
                    keep_late_edit(area, digest, &bytes)?;
                    reference(path, digest)?;
                    ctx.root.remove(path, &observed).map_err(failed)?;
                    QuarantineStatus::RemovedLateEdit { sha256: *digest }
                }
            }
            Observed::Symlink { target } => {
                if recorded.is_none()
                    && versions
                        .iter()
                        .any(|v| v.symlink_target.as_deref() == Some(target.as_slice()))
                {
                    ctx.root.remove(path, &observed).map_err(failed)?;
                    QuarantineStatus::Removed
                } else {
                    let digest = sha256(target);
                    keep_late_edit(area, &digest, target)?;
                    reference(path, &digest)?;
                    ctx.root.remove(path, &observed).map_err(failed)?;
                    QuarantineStatus::RemovedLateEdit { sha256: digest }
                }
            }
        };
        hook(InstallPoint::AfterOriginalRemoved(index)).map_err(|_| InstallError::Crashed)?;
        let (text, late) = status_text(&status);
        conn.execute(
            "UPDATE native_rebootstrap_quarantine SET status = ?4, late_sha256 = ?5 \
             WHERE group_id = ?1 AND recovery_id = ?2 AND path = ?3",
            (group.as_str(), recovery_id, path, text, late),
        )?;
        hook(InstallPoint::AfterQuarantineItem(index)).map_err(|_| InstallError::Crashed)?;
    }
    Ok(())
}

/// The copy a recorded digest names is in the area and reads back.
fn keep_late_edit_present(area: &RecoveryArea, digest: &[u8; 32]) -> Result<(), InstallError> {
    let bytes = area.read_late_edit(digest).map_err(|e| blocked_by(area_failure(e)))?;
    if sha256(&bytes) != *digest {
        return Err(blocked_by(BlockedReason::PreservationFailed(
            PreservationFailure::CopyVerification { item: "late edit".into() },
        )));
    }
    Ok(())
}

/// Saves `bytes` in the area under `digest` and reads them back.
fn keep_late_edit(
    area: &RecoveryArea,
    digest: &[u8; 32],
    bytes: &[u8],
) -> Result<(), InstallError> {
    area.write_late_edit(digest, bytes).map_err(|e| blocked_by(area_failure(e)))?;
    if area.read_late_edit(digest).map_err(|e| blocked_by(area_failure(e)))? != bytes {
        return Err(blocked_by(BlockedReason::PreservationFailed(
            PreservationFailure::CopyVerification { item: "late edit".into() },
        )));
    }
    Ok(())
}

// --- the transaction ---------------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn install_in_tx(
    conn: &Connection,
    ctx: &InstallContext<'_>,
    group: &FolderGroupId,
    area: &RecoveryArea,
    recovery_id: &str,
    manifest: &Manifest,
    manifest_sha256: &[u8; 32],
    hook: &mut dyn FnMut(InstallPoint) -> Result<(), Crash>,
) -> Result<Installed, InstallError> {
    // The target is read from the stored bytes here, as a restart would.
    let verified = verify_target_in_area(area, group).map_err(|e| {
        InstallError::Blocked(BlockedReason::PreservationFailed(
            PreservationFailure::TargetNotVerifiable { detail: e.to_string() },
        ))
    })?;
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let status = rebootstrap_status(&tx, group)?
        .ok_or_else(|| InstallError::NotInstallable("no rebootstrap".into()))?;
    if status.state != RebootstrapState::Quarantining || status.recovery_id != recovery_id {
        return Err(InstallError::NotInstallable(format!("it is {:?}", status.state)));
    }
    let unfinished: i64 = tx.query_row(
        "SELECT COUNT(*) FROM native_rebootstrap_quarantine \
         WHERE group_id = ?1 AND recovery_id = ?2 AND status IN ('pending', 'removing')",
        (group.as_str(), recovery_id),
        |row| row.get(0),
    )?;
    if unfinished > 0 {
        return Err(InstallError::NotInstallable("an original is not yet quarantined".into()));
    }
    let marker = InstallAuthority::issue(&tx, group, recovery_id)?;
    let installed = crate::native_checkpoint_install::install_checkpoint(
        &tx,
        group,
        verified,
        InstallKind::Rebootstrap(RebootstrapBarrier {
            authority: &marker,
            manifest,
            manifest_sha256,
            items_root: &ctx.preserve.items_root,
            closure_key: ctx.closure_key,
        }),
        &mut |step| hook(InstallPoint::InTransaction(step)),
    )
    .map_err(InstallError::from)?;
    set_state(&tx, group, "catching_up", ctx.preserve.now_unix)?;
    hook(InstallPoint::InTransaction(InstallStep::Recorded)).map_err(|_| InstallError::Crashed)?;
    tx.commit()?;
    hook(InstallPoint::AfterCommit).map_err(|_| InstallError::Crashed)?;

    Ok(Installed {
        recovery_id: recovery_id.to_owned(),
        new_author: installed.new_author.ok_or_else(|| {
            InstallError::NotInstallable("a rebootstrap install rotates this device".into())
        })?,
        old_authors: manifest.old_authors.clone(),
    })
}

fn installed_summary(
    conn: &Connection,
    recovery_id: &str,
    manifest: &Manifest,
) -> Result<Installed, InstallError> {
    let record = crate::author_incarnation::incarnation_record(conn)?
        .ok_or_else(|| InstallError::NotInstallable("no incarnation".into()))?;
    Ok(Installed {
        recovery_id: recovery_id.to_owned(),
        new_author: record.author,
        old_authors: manifest.old_authors.clone(),
    })
}
