//! What a rebootstrap set aside for the user: versions another device wrote that the replacing
//! state does not contain (recovery items), and this device's own changes that could not be
//! replayed. They are kept until the user acts: a version can be restored as one ordinary new
//! write or discarded; nothing here deletes anything on its own. The store belongs to the
//! device, not to a group: removing a group keeps its items.

use std::sync::Arc;

use yadorilink_replica_domain::file::{FileVersion, RecordKind};
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sync_sqlite::local_author::LocalAuthor;
use yadorilink_sync_sqlite::native_rebootstrap_replay::{
    held_own_units, retry_replay_unit, ReplayContext, RetryError,
};
use yadorilink_sync_sqlite::native_recovery_items::{
    complete_unavailable_item, discard_recovery_item, groups_with_preserved_data,
    list_recovery_items, restore_recovery_item, unavailable_items, ItemContent, ItemKind,
    RestoreError,
};
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::daemon_state::DaemonState;
use crate::native_rebootstrap::{DaemonContent, RECOVERY_FETCH_PASS_CAP};

/// The default total size of recovery items above which status warns.
pub const RECOVERY_ITEMS_WARN_BYTES_DEFAULT: u64 = 1 << 30;

/// The size above which status warns, from `YADORILINK_RECOVERY_ITEMS_WARN_BYTES` when set.
pub fn recovery_items_warn_bytes() -> u64 {
    std::env::var("YADORILINK_RECOVERY_ITEMS_WARN_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(RECOVERY_ITEMS_WARN_BYTES_DEFAULT)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreservedKind {
    /// A version of another device that the replacing state does not contain.
    RemoteOnly,
    /// A version above the cutoff at which the replacing state closes its author.
    BeyondClosureCutoff,
    /// Own changes of this device that were not replayed on top of the replacing state.
    OwnUnit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreservedItem {
    pub kind: PreservedKind,
    pub group_id: String,
    /// The group is no longer linked on this device.
    pub group_removed: bool,
    /// The item's id; for an own unit, `<recovery id>:<unit>`.
    pub item_id: String,
    /// The path of a version; the first path of an own unit.
    pub path: String,
    /// Every path an own unit touches.
    pub paths: Vec<String>,
    /// `complete`, `unavailable` or `record_unavailable`; empty for an own unit.
    pub content: String,
    pub size: u64,
    pub blocks_held: u32,
    pub blocks_total: u32,
    /// For an own unit: the recovery area that holds its signed deltas and file copies.
    pub recovery_id: String,
    /// For an own unit: its originals were moved out of the folder into that area.
    pub originals_quarantined: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreservedSummary {
    pub total: u32,
    pub content_unavailable: u32,
    pub record_unavailable: u32,
    pub bytes: u64,
    pub unreplayed_own_units: u32,
    pub warn_bytes: u64,
    /// The total size of the items is above `warn_bytes`.
    pub warn: bool,
}

#[derive(Debug)]
pub enum PreservedError {
    NotFound,
    /// A rebootstrap of the group is running.
    Busy,
    /// This device may not author into the group now (a viewer, revoked, or the group removed).
    NotAWriter,
    /// The item holds no version record.
    RecordUnavailable,
    /// The item holds the record but its bytes cannot be obtained.
    ContentUnavailable,
    Failed(String),
}

impl std::fmt::Display for PreservedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no such preserved item"),
            Self::Busy => {
                write!(f, "a rebootstrap of this group is running; try again when it ends")
            }
            Self::NotAWriter => write!(f, "this device may not write to the group"),
            Self::RecordUnavailable => {
                write!(f, "the item holds no record of the version, so it cannot be restored")
            }
            Self::ContentUnavailable => {
                write!(f, "the version's content is not available from any connected device")
            }
            Self::Failed(why) => write!(f, "{why}"),
        }
    }
}

impl From<SyncSqliteError> for PreservedError {
    fn from(error: SyncSqliteError) -> Self {
        match error {
            SyncSqliteError::GroupFrozen { .. } => Self::Busy,
            other => Self::Failed(other.to_string()),
        }
    }
}

fn linked_groups(state: &DaemonState) -> Vec<String> {
    state
        .replica_coordinator
        .link_repository()
        .list_links()
        .map(|links| links.into_iter().map(|link| link.group_id).collect())
        .unwrap_or_default()
}

/// Everything the device keeps for the user: the items and the units not replayed, of every
/// group including removed ones.
pub async fn list(state: &Arc<DaemonState>) -> Result<Vec<PreservedItem>, PreservedError> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || list_blocking(&state))
        .await
        .map_err(|e| PreservedError::Failed(e.to_string()))?
}

fn list_blocking(state: &Arc<DaemonState>) -> Result<Vec<PreservedItem>, PreservedError> {
    let linked = linked_groups(state);
    let (items_root, recovery_root) =
        (crate::device_config::recovery_items_root(), crate::device_config::recovery_root());
    let mut out = Vec::new();
    state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            for group in groups_with_preserved_data(conn)? {
                let removed = !linked.contains(&group.0);
                let unavailable: std::collections::BTreeMap<String, FileVersion> =
                    unavailable_items(conn, &items_root, &group)?
                        .into_iter()
                        .map(|(item, record)| (item.item_id, record))
                        .collect();
                for item in list_recovery_items(conn, &group)? {
                    let held = item.retained_blocks.len() as u32;
                    let total = unavailable
                        .get(&item.item_id)
                        .map_or(held, |record| record.blocks.len() as u32);
                    out.push(PreservedItem {
                        kind: match item.kind {
                            ItemKind::RemoteOnly => PreservedKind::RemoteOnly,
                            ItemKind::BeyondClosureCutoff => PreservedKind::BeyondClosureCutoff,
                        },
                        group_id: group.0.clone(),
                        group_removed: removed,
                        item_id: item.item_id,
                        path: item.path.0,
                        paths: Vec::new(),
                        content: content_name(item.content).into(),
                        size: item.size,
                        blocks_held: held,
                        blocks_total: total,
                        recovery_id: item.source_recovery_id,
                        originals_quarantined: false,
                    });
                }
                for unit in held_own_units(conn, &recovery_root, &group)? {
                    out.push(PreservedItem {
                        kind: PreservedKind::OwnUnit,
                        group_id: group.0.clone(),
                        group_removed: removed,
                        item_id: format!("{}:{}", unit.recovery_id, unit.unit),
                        path: unit.paths.first().cloned().unwrap_or_default(),
                        paths: unit.paths,
                        content: String::new(),
                        size: 0,
                        blocks_held: 0,
                        blocks_total: 0,
                        recovery_id: unit.recovery_id,
                        originals_quarantined: unit.originals_quarantined,
                    });
                }
            }
            Ok(())
        })
        .map_err(PreservedError::from)?;
    Ok(out)
}

fn content_name(content: ItemContent) -> &'static str {
    match content {
        ItemContent::Complete => "complete",
        ItemContent::Unavailable => "unavailable",
        ItemContent::RecordUnavailable => "record_unavailable",
    }
}

/// What `status` reports about the device's preserved data.
pub fn summary(state: &Arc<DaemonState>) -> PreservedSummary {
    let mut summary =
        PreservedSummary { warn_bytes: recovery_items_warn_bytes(), ..Default::default() };
    let Ok(items) = list_blocking(state) else { return summary };
    for item in items {
        match item.kind {
            PreservedKind::OwnUnit => summary.unreplayed_own_units += 1,
            _ => {
                summary.total += 1;
                summary.bytes += item.size;
                match item.content.as_str() {
                    "unavailable" => summary.content_unavailable += 1,
                    "record_unavailable" => summary.record_unavailable += 1,
                    _ => {}
                }
            }
        }
    }
    summary.warn = summary.bytes > summary.warn_bytes;
    summary
}

/// Deletes one item: its row, then its files. The only thing that ever does.
pub async fn discard(
    state: &Arc<DaemonState>,
    group: &str,
    item_id: &str,
) -> Result<(), PreservedError> {
    let (db, group, item_id) =
        (state.replica_coordinator.database(), FolderGroupId(group.to_owned()), item_id.to_owned());
    let items_root = crate::device_config::recovery_items_root();
    let found = tokio::task::spawn_blocking(move || {
        db.write::<_, SyncSqliteError>(|conn| {
            discard_recovery_item(conn, &items_root, &group, &item_id)
        })
    })
    .await
    .map_err(|e| PreservedError::Failed(e.to_string()))??;
    if found {
        Ok(())
    } else {
        Err(PreservedError::NotFound)
    }
}

/// Fetches the missing blocks of every item of `group` whose bytes are incomplete, from the
/// connected peers within a time cap, and completes the ones that arrived whole. Best effort;
/// an item that cannot be completed stays as it is.
pub async fn complete_unavailable_items(state: &Arc<DaemonState>, group: &FolderGroupId) {
    let items_root = crate::device_config::recovery_items_root();
    let pending = {
        let (db, group, root) =
            (state.replica_coordinator.database(), group.clone(), items_root.clone());
        match tokio::task::spawn_blocking(move || {
            db.read::<_, SyncSqliteError>(|conn| unavailable_items(conn, &root, &group))
        })
        .await
        {
            Ok(Ok(pending)) => pending,
            _ => return,
        }
    };
    if pending.is_empty() {
        return;
    }
    let content = DaemonContent::for_group(state, group, RECOVERY_FETCH_PASS_CAP);
    for (item, record) in pending {
        if record.meta.record_kind != RecordKind::File {
            continue;
        }
        content.fetch_missing(&record).await;
        let Some(bytes) = content.read_after_fetch(&record) else { continue };
        let (db, group, root) =
            (state.replica_coordinator.database(), group.clone(), items_root.clone());
        let id = item.item_id.clone();
        let completed = tokio::task::spawn_blocking(move || {
            db.write::<_, SyncSqliteError>(|conn| {
                complete_unavailable_item(conn, &root, &group, &id, &bytes)
                    .map_err(|e| SyncSqliteError::CorruptState(format!("{e:?}")))
            })
        })
        .await;
        if !matches!(completed, Ok(Ok(()))) {
            tracing::warn!(item = %item.item_id, "recovery item: could not complete it from the fetched blocks");
        }
    }
}

/// Restores a version item as one ordinary new write at its original path, with a new
/// identity: the original author and dot are not restored. The item stays.
pub async fn restore(
    state: &Arc<DaemonState>,
    group: &str,
    item_id: &str,
) -> Result<(), PreservedError> {
    let group = FolderGroupId(group.to_owned());
    if !linked_groups(state).contains(&group.0)
        || !crate::native_rebootstrap::is_writer(state, &group)
    {
        return Err(PreservedError::NotAWriter);
    }
    // Missing blocks are asked for first: a restore completes an unavailable item when it can.
    let known = {
        let (db, g) = (state.replica_coordinator.database(), group.clone());
        tokio::task::spawn_blocking(move || {
            db.read::<_, SyncSqliteError>(|conn| list_recovery_items(conn, &g))
        })
        .await
        .map_err(|e| PreservedError::Failed(e.to_string()))??
    };
    let item = known.into_iter().find(|i| i.item_id == item_id).ok_or(PreservedError::NotFound)?;
    if item.content == ItemContent::Unavailable {
        complete_unavailable_items(state, &group).await;
    }
    let (state_for_write, group_for_write, item_id) =
        (state.clone(), group.clone(), item_id.to_owned());
    tokio::task::spawn_blocking(move || {
        restore_blocking(&state_for_write, &group_for_write, &item_id)
    })
    .await
    .map_err(|e| PreservedError::Failed(e.to_string()))??;
    // The restored write is published like any local change, and the materializer places it.
    state.flush_pending_native_checkpoint_for_group(group.as_str()).await;
    state.replica_coordinator.notify_materialization_wake();
    Ok(())
}

fn restore_blocking(
    state: &Arc<DaemonState>,
    group: &FolderGroupId,
    item_id: &str,
) -> Result<(), PreservedError> {
    let key = state
        .device_signing_key()
        .ok_or_else(|| PreservedError::Failed("this device has no signing key".into()))?;
    let author = state
        .replica_coordinator
        .open_local_author(&state.device_id, key)
        .map_err(|e| PreservedError::Failed(e.to_string()))?;
    let items_root = crate::device_config::recovery_items_root();
    let db = state.replica_coordinator.database();
    let mut failure: Option<RestoreError> = None;
    state
        .replica_coordinator
        .with_local_author(&author, |current| {
            failure = None;
            db.write::<_, SyncSqliteError>(|conn| {
                let local = LocalAuthor::of_key(current);
                let mut import = |version: &FileVersion, bytes: &[u8]| -> Result<(), String> {
                    let mut hashes = Vec::new();
                    let mut offset = 0usize;
                    for block in &version.blocks {
                        let end = offset + block.size as usize;
                        let part = bytes
                            .get(offset..end)
                            .ok_or("the bytes are shorter than the version")?;
                        state.block_store.put(part).map_err(|e| e.to_string())?;
                        hashes.push(block.hash.0.clone());
                        offset = end;
                    }
                    crate::replica_coordinator::ReplicaCoordinator::record_recovered_block_provenance_in_tx(
                        conn,
                        group.as_str(),
                        &hashes,
                    )
                    .map_err(|e| e.to_string())
                };
                match restore_recovery_item(conn, &items_root, group, item_id, &local, &mut import)
                {
                    Ok(_) => Ok(()),
                    Err(RestoreError::Store(error)) => Err(error),
                    Err(other) => {
                        failure = Some(other);
                        Ok(())
                    }
                }
            })
        })
        .map_err(PreservedError::from)?;
    match failure {
        None => Ok(()),
        Some(RestoreError::NotFound) => Err(PreservedError::NotFound),
        Some(RestoreError::RecordUnavailable) => Err(PreservedError::RecordUnavailable),
        Some(RestoreError::ContentUnavailable) => Err(PreservedError::ContentUnavailable),
        Some(RestoreError::Corrupt(why) | RestoreError::Import(why)) => {
            Err(PreservedError::Failed(why))
        }
        Some(RestoreError::Store(error)) => Err(error.into()),
    }
}

/// Re-submits an own unit a rebootstrap held back (`item_id` is `<recovery id>:<unit>`) to the
/// replay's unit scheduler, as this device's current incarnation. The device must be a writer of
/// the group now; the unit is resolved in the transaction that authors it.
pub async fn retry(
    state: &Arc<DaemonState>,
    group: &str,
    item_id: &str,
) -> Result<(), PreservedError> {
    let group = FolderGroupId(group.to_owned());
    let (recovery_id, unit) = item_id
        .rsplit_once(':')
        .and_then(|(id, unit)| Some((id.to_owned(), unit.parse::<usize>().ok()?)))
        .ok_or(PreservedError::NotFound)?;
    if !linked_groups(state).contains(&group.0) {
        return Err(PreservedError::NotAWriter);
    }
    let (state_for_write, group_for_write) = (state.clone(), group.clone());
    tokio::task::spawn_blocking(move || {
        retry_blocking(&state_for_write, &group_for_write, &recovery_id, unit)
    })
    .await
    .map_err(|e| PreservedError::Failed(e.to_string()))??;
    state.flush_pending_native_checkpoint_for_group(group.as_str()).await;
    state.replica_coordinator.notify_materialization_wake();
    Ok(())
}

fn retry_blocking(
    state: &Arc<DaemonState>,
    group: &FolderGroupId,
    recovery_id: &str,
    unit: usize,
) -> Result<(), PreservedError> {
    let key = state
        .device_signing_key()
        .ok_or_else(|| PreservedError::Failed("this device has no signing key".into()))?;
    let author = state
        .replica_coordinator
        .open_local_author(&state.device_id, key)
        .map_err(|e| PreservedError::Failed(e.to_string()))?;
    let authority =
        crate::native_rebootstrap::DaemonAuthority { state: state.clone(), group: group.clone() };
    let recovery_root = crate::device_config::recovery_root();
    let db = state.replica_coordinator.database();
    let mut failure: Option<RetryError> = None;
    state
        .replica_coordinator
        .with_local_author(&author, |current| {
            failure = None;
            db.write::<_, SyncSqliteError>(|conn| {
                let local = LocalAuthor::of_key(current);
                let ctx = ReplayContext {
                    recovery_root: &recovery_root,
                    authority: &authority,
                    author: &local,
                    now_unix: crate::native_rebootstrap::now_unix(),
                };
                match retry_replay_unit(conn, &ctx, group, recovery_id, unit, &mut |_| Ok(())) {
                    Ok(_) => Ok(()),
                    Err(RetryError::Store(error)) => Err(error),
                    Err(other) => {
                        failure = Some(other);
                        Ok(())
                    }
                }
            })
        })
        .map_err(PreservedError::from)?;
    match failure {
        None => Ok(()),
        Some(RetryError::NotHeld) => Err(PreservedError::NotFound),
        Some(RetryError::NotAWriter) => Err(PreservedError::NotAWriter),
        Some(RetryError::RebootstrapRunning) => Err(PreservedError::Busy),
        Some(RetryError::Refused) => Err(PreservedError::Failed(
            "the group's current state refuses these changes; they stay held".into(),
        )),
        Some(RetryError::Blocked(reason)) => Err(PreservedError::Failed(format!("{reason:?}"))),
        Some(RetryError::Crashed) => Err(PreservedError::Failed("interrupted".into())),
        Some(RetryError::Store(error)) => Err(error.into()),
    }
}

/// The groups whose rebootstrap is replacing their state now or is waiting to be continued.
pub fn rebootstrapping_groups(state: &Arc<DaemonState>) -> Vec<String> {
    let linked = linked_groups(state);
    state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            let mut groups = Vec::new();
            for group in &linked {
                let group = FolderGroupId(group.clone());
                if yadorilink_sync_sqlite::native_rebootstrap::rebootstrap_status(conn, &group)?
                    .is_some()
                {
                    groups.push(group.0);
                }
            }
            Ok(groups)
        })
        .unwrap_or_default()
}
