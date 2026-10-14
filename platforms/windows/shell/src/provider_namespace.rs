//! Showing a provider root's namespace in its sync root.
//!
//! The daemon's namespace of a root is a tree of items (stable item ids, a parent, a name, a
//! kind, a size and a time). This module makes the sync root directory show that tree as Cloud
//! Files placeholders: a placeholder per file and per directory, each carrying its item id as the
//! placeholder identity, so a later fetch, eviction or change can name the item.
//!
//! It only ever changes what is a placeholder of a provider item and is in sync (untouched by the
//! user). A name the user occupies with a file of their own, and a placeholder the user modified,
//! are left alone: what such a thing means is for the daemon to decide when it is reported to it,
//! never for the namespace view to guess. No directory listing is trusted unless every page of it
//! was confirmed, so a daemon that cannot answer never reads as "the folder is empty".

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows_sys::Win32::Storage::CloudFilters::{
    CfConvertToPlaceholder, CfDehydratePlaceholder, CfGetPlaceholderInfo, CfRevertPlaceholder,
    CfSetInSyncState, CfUpdatePlaceholder, CF_CONVERT_FLAG_MARK_IN_SYNC, CF_DEHYDRATE_FLAG_NONE,
    CF_FS_METADATA, CF_IN_SYNC_STATE_IN_SYNC, CF_PLACEHOLDER_BASIC_INFO, CF_PLACEHOLDER_INFO_BASIC,
    CF_REVERT_FLAG_NONE, CF_SET_IN_SYNC_FLAG_NONE, CF_UPDATE_FLAG_MARK_IN_SYNC,
    CF_UPDATE_FLAG_VERIFY_IN_SYNC,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, FILE_ATTRIBUTE_DIRECTORY, FILE_BASIC_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use yadorilink_ipc_proto::shellipc::{EntryKind, ProviderItem};

use crate::cfapi::{create_item_placeholder, decode_item_identity};
use crate::provider_authoring::AdoptError;
use crate::stage_ledger::StageLedger;
use yadorilink_fs_platform::durable_dir::DurableNamespace;

/// `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` and `FILE_ATTRIBUTE_RECALL_ON_OPEN`: the attributes of
/// a placeholder whose content is not on the disk.
const RECALL_ATTRIBUTES: u32 = 0x0040_0000 | 0x0004_0000;

const ERROR_CLOUD_FILE_IN_USE: i32 = 0x8007_016Au32 as i32;
const ERROR_SHARING_VIOLATION: i32 = 0x8007_0020u32 as i32;

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    // Past MAX_PATH a raw wide-character call needs the verbatim form.
    yadorilink_fs_platform::long_path::for_win32(path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// An open handle, closed on drop.
struct Handle(HANDLE);

#[cfg(test)]
thread_local! {
    /// Makes [`flush_state`] fail, to see what a caller does when the state change it just made
    /// cannot be shown to be on the disk.
    static FLUSH_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Puts the state change just made through `handle` (a dehydrate, a revert) on the disk before
/// the caller reports it as done. The Cloud Files API documents no durability for these calls, so
/// a power loss could return the old state after the report: a dehydrate that comes back leaves
/// the older version's bytes under a newer version's size and time.
fn flush_state(handle: &Handle) -> Result<(), String> {
    #[cfg(test)]
    if FLUSH_FAILS.with(|f| f.get()) {
        return Err("injected flush failure".into());
    }
    // SAFETY: `handle` is open for writing.
    if unsafe { FlushFileBuffers(handle.0) } == 0 {
        return Err(format!("FlushFileBuffers: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

impl Handle {
    /// Opens `path` itself (a reparse point is not followed, and nothing is hydrated).
    fn open(path: &Path, access: u32) -> std::io::Result<Self> {
        Self::open_sharing(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
    }

    /// Like [`Handle::open`], with the sharing the caller allows others while it is open.
    fn open_sharing(path: &Path, access: u32, share: u32) -> std::io::Result<Self> {
        let name = wide(path);
        // SAFETY: `name` is NUL-terminated.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                share,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle as isize == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: opened by `CreateFileW` above and closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// What the Cloud Files driver and the file system say about one name in a sync root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceholderInfo {
    /// The item the placeholder was created for; `None` for a placeholder of another kind.
    pub item_id: Option<Vec<u8>>,
    /// The placeholder has not been modified by the user since it was last made current.
    pub in_sync: bool,
    pub is_dir: bool,
    pub size: u64,
    /// Last write time, in 100 ns ticks since 1601.
    pub mtime_ticks: u64,
    /// The content is not on the disk.
    pub dehydrated: bool,
}

/// The placeholder at `path`, or `None` when the name does not exist or is not a placeholder.
pub fn placeholder_info(path: &Path) -> Option<PlaceholderInfo> {
    use std::os::windows::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).ok()?;
    let handle = Handle::open(path, FILE_READ_ATTRIBUTES).ok()?;
    const HEADROOM: usize = 64;
    let mut buffer = vec![0u8; std::mem::size_of::<CF_PLACEHOLDER_BASIC_INFO>() + HEADROOM];
    let mut returned = 0u32;
    // SAFETY: `buffer` holds a full `CF_PLACEHOLDER_BASIC_INFO` plus room for the identity.
    let result = unsafe {
        CfGetPlaceholderInfo(
            handle.0,
            CF_PLACEHOLDER_INFO_BASIC,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len() as u32,
            &mut returned,
        )
    };
    if result < 0 {
        return None;
    }
    // SAFETY: the call succeeded, so at least a full structure was written.
    let info: CF_PLACEHOLDER_BASIC_INFO =
        unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast()) };
    let offset = std::mem::offset_of!(CF_PLACEHOLDER_BASIC_INFO, FileIdentity);
    let length = info.FileIdentityLength as usize;
    let identity = offset
        .checked_add(length)
        .filter(|end| *end <= buffer.len())
        .map(|end| &buffer[offset..end]);
    let attributes = metadata.file_attributes();
    Some(PlaceholderInfo {
        item_id: identity.and_then(decode_item_identity).map(<[u8]>::to_vec),
        in_sync: info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC,
        is_dir: attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        size: metadata.file_size(),
        mtime_ticks: metadata.last_write_time(),
        dehydrated: attributes & RECALL_ATTRIBUTES != 0,
    })
}

/// The stable identity (volume serial and file index) of the object `handle` is open on.
fn handle_file_id(handle: &Handle) -> Option<u128> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    // SAFETY: the handle is open and the structure is plain data the call fills.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
        return None;
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Some((u128::from(info.dwVolumeSerialNumber) << 64) | u128::from(index))
}

/// The stable identity of the object at `path`, read without following a reparse point and
/// without hydrating anything.
pub fn file_id(path: &Path) -> Option<u128> {
    handle_file_id(&Handle::open(path, FILE_READ_ATTRIBUTES).ok()?)
}

/// Deletes the file at `path` only if it is the object with `file_id` and, when `usn` is given,
/// still at that USN. The handle allows no writer in (one already in makes the open fail), and the
/// identity and the USN are read from that very handle the deletion is set on, so a replacement or
/// a save that arrives meanwhile is not removed.
pub fn remove_object(path: &Path, file_id: u128, usn: Option<i64>) -> Result<(), AdoptError> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };
    const DELETE: u32 = 0x0001_0000;
    let handle = Handle::open_sharing(
        path,
        DELETE | FILE_READ_ATTRIBUTES | GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
    )
    .map_err(|e| AdoptError::Failed(e.to_string()))?;
    if handle_file_id(&handle) != Some(file_id) {
        return Err(AdoptError::Failed("not the object the request described".into()));
    }
    if let Some(expected) = usn {
        usn_guard(Some(expected), file_usn(handle.0))?;
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    // SAFETY: `handle` is open with DELETE access; the structure outlives the call.
    let ok = unsafe {
        SetFileInformationByHandle(
            handle.0,
            FileDispositionInfo,
            std::ptr::addr_of!(disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(AdoptError::Failed(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

/// A name the host will create in a sync root: one component, nothing the file system reads as
/// a path, a stream or a device.
pub fn valid_component(name: &str) -> bool {
    !is_reserved_device_name(name)
        && !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.ends_with(['.', ' '])
        && !name.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|', '\0'])
        && !name.chars().any(|c| (c as u32) < 0x20)
}

/// `CON`, `NUL`, `COM1`... (also with an extension): names the file system treats as devices.
fn is_reserved_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end().to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|digit| matches!(digit.as_bytes(), [b'0'..=b'9']))
        })
}

fn unix_nanos_to_ticks(unix_nanos: i64) -> u64 {
    const EPOCH_TICKS: i64 = 116_444_736_000_000_000;
    (unix_nanos / 100 + EPOCH_TICKS).max(0) as u64
}

/// An item as the sync root shows it: where it is, and what the daemon said about it when it was
/// shown. This is the host's knowledge of the provider state: a local change is judged against it
/// (the version the user saw is the base of an edit; the folder an item was in is the one a move
/// leaves).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShownItem {
    pub path: PathBuf,
    pub parent_item_id: Vec<u8>,
    pub name: String,
    pub directory: bool,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    /// The 40-byte content version identifier, exactly as the daemon issued it.
    pub content_version: Vec<u8>,
    pub parent_generation: u64,
}

impl ShownItem {
    fn of(path: PathBuf, item: &ProviderItem) -> Self {
        Self {
            path,
            parent_item_id: item.parent_item_id.clone(),
            name: item.name.clone(),
            directory: item.entry_kind == EntryKind::Directory as i32,
            size: item.size,
            mtime_unix_nanos: item.mtime_unix_nanos,
            content_version: item.content_version.clone(),
            parent_generation: item.parent_generation,
        }
    }
}

/// The items shown, by item id.
pub type ShownItems = HashMap<Vec<u8>, ShownItem>;

/// Makes the sync root at `root_path` show the namespace of provider root `root_id`: creates the
/// missing placeholders, brings stale ones up to date and removes placeholders of items that no
/// longer exist. `None` when any directory's listing could not be confirmed (nothing is then
/// removed below it); otherwise the items shown.
pub fn sync_namespace(
    root_id: &[u8],
    root_path: &Path,
    previous: &ShownItems,
    protected: &HashSet<String>,
) -> Option<ShownItems> {
    sync_namespace_from(
        &Daemon,
        &StageLedger::for_root(root_id),
        root_id,
        root_path,
        previous,
        protected,
    )
}

/// The daemon's side of a walk: the children of an item (empty: the root), every page, or `None`
/// when they could not be confirmed.
pub(crate) trait NamespaceSource {
    fn children(&self, root_id: &[u8], parent_item: &[u8]) -> Option<Vec<ProviderItem>>;
}

struct Daemon;

impl NamespaceSource for Daemon {
    fn children(&self, root_id: &[u8], parent_item: &[u8]) -> Option<Vec<ProviderItem>> {
        crate::provider_client::enumerate_children(root_id, parent_item)
    }
}

/// What one walk reads and compares against, shared by every directory of it.
struct Walk<'a> {
    source: &'a dyn NamespaceSource,
    ledger: &'a StageLedger,
    root_id: &'a [u8],
    previous: &'a ShownItems,
    protected: &'a HashSet<String>,
}

/// The sync root's capability, asked before anything is authored or shown in it: `Err` when the
/// volume was refused by the durable-namespace probe (`Unsupported`, `Unknown`); the closed
/// global gate keeps the pre-validation behaviour and is `Ok`.
pub fn root_offers_durable_namespace(root_path: &Path) -> Result<(), String> {
    DurableNamespace::open_unless_gate_closed(root_path)
        .map(|_| ())
        .map_err(|error| format!("it does not offer durable namespace changes: {error}"))
}

/// [`sync_namespace`] with the daemon's namespace supplied.
pub(crate) fn sync_namespace_from(
    source: &dyn NamespaceSource,
    ledger: &StageLedger,
    root_id: &[u8],
    root_path: &Path,
    previous: &ShownItems,
    protected: &HashSet<String>,
) -> Option<ShownItems> {
    // A volume the durable-namespace probe refused (ReFS, exFAT, SMB, a probe that could not
    // run) is neither populated nor cleaned: the walk is not confirmed and nothing is touched.
    // `Ok(None)` is the closed global gate, where the host keeps its pre-validation behaviour.
    if let Err(reason) = root_offers_durable_namespace(root_path) {
        eprintln!("yadorilink-cfapi-host: not walking {}: {reason}", root_path.display());
        return None;
    }
    // What a crash left of a placeholder's Stage step goes first, by the exact paths recorded
    // before each was created; the walk below only ever creates new ones.
    let recovered =
        ledger.recover(&|path| placeholder_info(path).is_some_and(|i| i.item_id.is_some()));
    if !recovered.removed.is_empty() || !recovered.kept.is_empty() {
        eprintln!(
            "yadorilink-cfapi-host: Stage placeholders of an interrupted create: {} removed, {} kept",
            recovered.removed.len(),
            recovered.kept.len()
        );
    }
    let walk = Walk { source, ledger, root_id, previous, protected };
    let mut shown = ShownItems::new();
    let mut complete = true;
    sync_directory(&walk, root_path, &[], &mut shown, &mut complete);
    complete.then_some(shown)
}

fn sync_directory(
    walk: &Walk<'_>,
    directory: &Path,
    parent_item: &[u8],
    shown: &mut ShownItems,
    complete: &mut bool,
) {
    let Walk { previous, protected, .. } = *walk;
    let Some(items) = walk.source.children(walk.root_id, parent_item) else {
        *complete = false;
        return;
    };
    let wanted: HashMap<String, &ProviderItem> = items
        .iter()
        .filter(|item| {
            let valid = valid_component(&item.name);
            if !valid {
                eprintln!(
                    "yadorilink-cfapi-host: skipping an item with the unusable name {:?}",
                    item.name
                );
            }
            valid
        })
        .map(|item| (item.name.to_lowercase(), item))
        .collect();

    // What the daemon no longer has goes first, so a name that changed hands is free.
    if let Ok(entries) = std::fs::read_dir(directory) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            let path = entry.path();
            if protected.contains(&path.to_string_lossy().to_lowercase()) {
                continue;
            }
            let keep = wanted.get(&name).map(|item| item.item_id.clone());
            remove_if_stale(&path, keep.as_deref());
        }
    }

    for item in wanted.values() {
        let path = directory.join(&item.name);
        if protected.contains(&path.to_string_lossy().to_lowercase()) {
            // The user did something here that has not been reported yet: not touched. What is
            // inside is still walked when this is confirmed to be a folder, so convergence does
            // not stop below a rename waiting to be reported.
            if let Some(old) = previous.get(&item.item_id) {
                shown.insert(item.item_id.clone(), old.clone());
            }
            if item.entry_kind == EntryKind::Directory as i32
                && placeholder_info(&path).is_some_and(|info| {
                    info.is_dir && info.item_id.as_deref() == Some(item.item_id.as_slice())
                })
            {
                sync_directory(walk, &path, &item.item_id, shown, complete);
            }
            continue;
        }
        let directory_item = item.entry_kind == EntryKind::Directory as i32;
        if item.entry_kind == EntryKind::Symlink as i32 {
            eprintln!(
                "yadorilink-cfapi-host: {:?} is a symbolic link, which has no placeholder",
                item.name
            );
            continue;
        }
        match placeholder_info(&path) {
            None if path.symlink_metadata().is_ok() => {
                // The user's own file or folder holds the name.
                eprintln!(
                    "yadorilink-cfapi-host: {:?} is occupied by a local item; leaving it",
                    path.display()
                );
                continue;
            }
            None => {
                if let Err(error) = create_item_placeholder(
                    walk.ledger,
                    directory,
                    &item.name,
                    &item.item_id,
                    item.size,
                    item.mtime_unix_nanos,
                    directory_item,
                ) {
                    eprintln!(
                        "yadorilink-cfapi-host: could not create the placeholder {}: {error:?}",
                        path.display()
                    );
                    // Not shown: the walk is not complete and is tried again.
                    *complete = false;
                    continue;
                }
                // Shown only once the name holds the placeholder that was made for the item.
                if placeholder_info(&path).and_then(|info| info.item_id).as_deref()
                    != Some(item.item_id.as_slice())
                {
                    eprintln!(
                        "yadorilink-cfapi-host: {} is not the placeholder just created",
                        path.display()
                    );
                    *complete = false;
                    continue;
                }
            }
            Some(info) if info.item_id.as_deref() == Some(item.item_id.as_slice()) => {
                // A folder, or a file with no bytes whose size and time are what the daemon says,
                // that is not in sync is a new placeholder whose host stopped between its move
                // onto the name and the in-sync mark: nothing the user could have changed is
                // lost by marking it (a touched time or a written byte shows in the comparison).
                let unchanged = directory_item
                    || (info.dehydrated
                        && info.size == item.size
                        && info.mtime_ticks == unix_nanos_to_ticks(item.mtime_unix_nanos));
                let info = if !info.in_sync && unchanged {
                    match mark_in_sync(&path) {
                        Ok(()) => placeholder_info(&path).unwrap_or(info),
                        Err(error) => {
                            eprintln!(
                                "yadorilink-cfapi-host: could not mark {} in sync: {error}",
                                path.display()
                            );
                            // Still out of sync: the walk is not complete and is tried again.
                            *complete = false;
                            info
                        }
                    }
                } else {
                    info
                };
                if !directory_item && needs_update(&info, item) {
                    if let Err(error) = update_placeholder(&path, &info, item) {
                        eprintln!(
                            "yadorilink-cfapi-host: could not update the placeholder {}: {error}",
                            path.display()
                        );
                        // Still the old size and time: the walk is not complete and is tried
                        // again, and the revision is not acknowledged as shown.
                        *complete = false;
                    }
                }
            }
            // A placeholder of another item holds the name (and was not removed above because
            // the user changed it) or one this host did not create.
            Some(_) => continue,
        }
        // A placeholder the user changed keeps the version it was changed from: that is the base of
        // the edit, whatever the daemon holds by now.
        let dirty = placeholder_info(&path).is_some_and(|info| !info.in_sync && !info.is_dir);
        let entry = match previous.get(&item.item_id) {
            Some(old) if dirty => old.clone(),
            _ => ShownItem::of(path.clone(), item),
        };
        shown.insert(item.item_id.clone(), entry);
        if directory_item {
            sync_directory(walk, &path, &item.item_id, shown, complete);
        }
    }
}

fn needs_update(info: &PlaceholderInfo, item: &ProviderItem) -> bool {
    info.in_sync
        && (info.size != item.size
            || info.mtime_ticks != unix_nanos_to_ticks(item.mtime_unix_nanos))
}

/// Removes `path` when it is a placeholder of an item other than `keep`, untouched by the user.
/// A directory is emptied of such placeholders first and removed only if nothing else is in it.
fn remove_if_stale(path: &Path, keep: Option<&[u8]>) {
    let Some(info) = placeholder_info(path) else { return };
    let Some(item_id) = info.item_id.as_deref() else { return };
    if Some(item_id) == keep || !info.in_sync {
        return;
    }
    if info.is_dir {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                remove_if_stale(&entry.path(), None);
            }
        }
        let _ = std::fs::remove_dir(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

fn update_placeholder(
    path: &Path,
    info: &PlaceholderInfo,
    item: &ProviderItem,
) -> Result<(), String> {
    // A hydrated copy of an older version is dropped first; the daemon evicts it before
    // publishing, so this is only the repair of a missed eviction.
    if !info.dehydrated {
        evict(path, &item.item_id).map_err(|outcome| format!("{outcome:?}"))?;
    }
    let handle = Handle::open(path, GENERIC_READ | GENERIC_WRITE).map_err(|e| e.to_string())?;
    // The new size and time are never on the disk before the dehydrate is: a dehydrate that a
    // power loss returns, under the newer version's size and time, would pass for the new
    // version. This also covers a dehydrate whose own flush failed and was not retried.
    flush_state(&handle)?;
    let ticks = unix_nanos_to_ticks(item.mtime_unix_nanos) as i64;
    let metadata = CF_FS_METADATA {
        BasicInfo: FILE_BASIC_INFO {
            CreationTime: ticks,
            LastAccessTime: ticks,
            LastWriteTime: ticks,
            ChangeTime: ticks,
            FileAttributes: 0x80, // FILE_ATTRIBUTE_NORMAL
        },
        FileSize: item.size as i64,
    };
    let identity = crate::cfapi::encode_item_identity(&item.item_id);
    // SAFETY: `handle` is open for writing; the pointers outlive the call.
    let result = unsafe {
        CfUpdatePlaceholder(
            handle.0,
            &metadata,
            identity.as_ptr().cast(),
            identity.len() as u32,
            std::ptr::null(),
            0,
            // The call itself refuses a placeholder the user wrote to since it was in sync, so
            // there is no window between a check and the update.
            CF_UPDATE_FLAG_MARK_IN_SYNC | CF_UPDATE_FLAG_VERIFY_IN_SYNC,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result < 0 {
        if result == 0x8007_0172_u32 as i32 {
            // ERROR_CLOUD_FILE_NOT_IN_SYNC: the user's edit stays, untouched and not in sync.
            return Err("changed by the user meanwhile".to_string());
        }
        return Err(format!("CfUpdatePlaceholder: HRESULT {result:#x}"));
    }
    Ok(())
}

/// The USN of the file behind `handle` (`FSCTL_READ_FILE_USN_DATA`): it moves when the file is
/// written to, so two equal readings mean the content is the same. `Ok(None)`: the volume has no
/// (usable) change journal. `Err`: it could not be read, which is never taken for "no journal".
pub(crate) fn file_usn(handle: HANDLE) -> Result<Option<i64>, u32> {
    const FSCTL_READ_FILE_USN_DATA: u32 = 0x0009_00EB;
    read_usn(|out| {
        // READ_FILE_USN_DATA: accept record versions 2 and 3.
        let request: [u16; 2] = [2, 3];
        let mut returned = 0u32;
        // SAFETY: the buffers outlive the call and their sizes are passed alongside.
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_READ_FILE_USN_DATA,
                request.as_ptr().cast(),
                std::mem::size_of_val(&request) as u32,
                out.as_mut_ptr().cast(),
                out.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: plain thread-local read.
            return Err(unsafe { windows_sys::Win32::Foundation::GetLastError() });
        }
        Ok(returned as usize)
    })
}

const ERROR_MORE_DATA: u32 = 234;
const ERROR_JOURNAL_DELETE_IN_PROGRESS: u32 = 1178;
const ERROR_JOURNAL_NOT_ACTIVE: u32 = 1179;
const ERROR_INVALID_DATA: u32 = 13;

/// Runs `ioctl` (fills the buffer, returns the bytes written or the Win32 error) with a buffer
/// that grows while the record (it carries the file name) does not fit, and reads the USN out.
fn read_usn(mut ioctl: impl FnMut(&mut [u8]) -> Result<usize, u32>) -> Result<Option<i64>, u32> {
    let mut size = 1024;
    loop {
        let mut out = vec![0u8; size];
        match ioctl(&mut out) {
            Ok(returned) => {
                // USN_RECORD_V2: the USN follows two 8-byte file references; V3 has 16-byte ones.
                let at = match u16::from_le_bytes([out[4], out[5]]) {
                    2 => 24,
                    3 => 40,
                    _ => return Err(ERROR_INVALID_DATA),
                };
                if returned < at + 8 {
                    return Err(ERROR_INVALID_DATA);
                }
                return Ok(Some(i64::from_le_bytes(out[at..at + 8].try_into().unwrap())));
            }
            Err(ERROR_MORE_DATA) if size < 1 << 16 => size *= 4,
            Err(ERROR_JOURNAL_NOT_ACTIVE | ERROR_JOURNAL_DELETE_IN_PROGRESS) => return Ok(None),
            Err(error) => return Err(error),
        }
    }
}

/// How the file compares with the USN it was copied at. `copied` is `None` only when nothing was
/// copied (a folder): there is nothing to guard. A copy always carries a USN (the ingest refuses
/// a volume without a change journal), so once there is one, a USN that cannot be read now is not
/// "unchanged": the bind fails closed and the file is never marked in sync. (Known limit: the
/// journal's own id is not compared, so deleting and recreating the volume's change journal
/// between the copy and the bind, which resets file USNs, is not detected.)
pub(crate) fn usn_guard(
    copied: Option<i64>,
    now: Result<Option<i64>, u32>,
) -> Result<(), AdoptError> {
    match (copied, now) {
        (None, _) => Ok(()),
        (Some(expected), Ok(Some(actual))) if actual == expected => Ok(()),
        (Some(_), Ok(Some(_))) => Err(AdoptError::Changed),
        (Some(_), Ok(None)) => Err(AdoptError::Failed("USN guard unavailable".into())),
        (Some(_), Err(code)) => {
            Err(AdoptError::Failed(format!("USN guard unavailable: error {code}")))
        }
    }
}

/// Marks the placeholder at `path` in sync. A rename (the Stage placeholder's move onto its name)
/// clears the bit, and a placeholder that is not in sync reads as the user's unshared change:
/// it is never evicted and never brought up to date.
pub fn mark_in_sync(path: &Path) -> Result<(), String> {
    // Attribute access only: a handle opened for writing and closed reads as a modified file to
    // the virus scanner, which then opens the placeholder and fetches its whole content.
    let handle = Handle::open(path, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
        .map_err(|e| e.to_string())?;
    // SAFETY: `handle` is open for writing.
    let result = unsafe {
        CfSetInSyncState(
            handle.0,
            CF_IN_SYNC_STATE_IN_SYNC,
            CF_SET_IN_SYNC_FLAG_NONE,
            std::ptr::null_mut(),
        )
    };
    if result < 0 {
        return Err(format!("CfSetInSyncState: HRESULT {result:#x}"));
    }
    Ok(())
}

/// Binds the file or folder at `path` to the daemon's item: a plain one becomes a placeholder
/// carrying the item id (its content stays on the disk, in sync), and a placeholder is marked in
/// sync (its identity is the item's already, and the daemon now holds what is on the disk).
/// `file_id` is the object that may be bound. `usn` is the file's USN when its bytes were copied
/// for the daemon: the platform's own USN guards (`InSyncUsn`, `ConvertUsn`) are not used, since
/// the calls advance the USN themselves. Instead the file is opened so that no writer can be in
/// or enter (a writer already in makes the open fail), and identity and USN are compared on that
/// handle: what is compared is what is marked. A file written to since the copy (the same size
/// and time included) stays not in sync ([`AdoptError::Changed`]) and is copied again next pass.
pub fn bind_to_item(
    path: &Path,
    item_id: &[u8],
    file_id: u128,
    usn: Option<i64>,
) -> Result<(), AdoptError> {
    let handle = Handle::open_sharing(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
    )
    .map_err(|e| AdoptError::Failed(e.to_string()))?;
    if handle_file_id(&handle) != Some(file_id) {
        return Err(AdoptError::Failed("not the object the request described".into()));
    }
    usn_guard(usn, file_usn(handle.0))?;
    let identity = crate::cfapi::encode_item_identity(item_id);
    let result = if placeholder_info(path).is_some() {
        // SAFETY: `handle` is open for writing.
        unsafe {
            CfSetInSyncState(
                handle.0,
                CF_IN_SYNC_STATE_IN_SYNC,
                CF_SET_IN_SYNC_FLAG_NONE,
                std::ptr::null_mut(),
            )
        }
    } else {
        // SAFETY: `handle` is open for writing; `identity` outlives the call.
        unsafe {
            CfConvertToPlaceholder(
                handle.0,
                identity.as_ptr().cast(),
                identity.len() as u32,
                CF_CONVERT_FLAG_MARK_IN_SYNC,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }
    };
    if result < 0 {
        return Err(AdoptError::Failed(format!("HRESULT {result:#x}")));
    }
    Ok(())
}

/// Makes the placeholder at `path` an ordinary file again (its bytes stay, its item identity
/// goes): the file is the user's own and is no longer any item.
pub fn revert_to_plain(path: &Path) -> Result<(), String> {
    let handle = Handle::open(path, GENERIC_READ | GENERIC_WRITE).map_err(|e| e.to_string())?;
    // SAFETY: `handle` is open for writing.
    let result =
        unsafe { CfRevertPlaceholder(handle.0, CF_REVERT_FLAG_NONE, std::ptr::null_mut()) };
    if result < 0 {
        return Err(format!("HRESULT {result:#x}"));
    }
    flush_state(&handle)
}

/// How an eviction request ended.
#[derive(Debug, PartialEq, Eq)]
pub enum EvictOutcome {
    /// The local content was dropped; the placeholder stays.
    Evicted,
    /// There was no local content (already dehydrated, or the item is not shown).
    NotMaterialized,
    /// A process holds the file open; the daemon retries this item.
    Busy,
    Error(String),
}

/// Drops the local content of the placeholder at `path`, which must be the placeholder of
/// `item_id` (a different identity there is never touched).
pub fn evict(path: &Path, item_id: &[u8]) -> Result<(), EvictOutcome> {
    let Some(info) = placeholder_info(path) else { return Err(EvictOutcome::NotMaterialized) };
    if info.item_id.as_deref() != Some(item_id) {
        return Err(EvictOutcome::Error(format!(
            "{} is not the placeholder of the requested item",
            path.display()
        )));
    }
    if info.dehydrated {
        return Err(EvictOutcome::NotMaterialized);
    }
    // A file the user has changed and not shared yet is the only copy of that change.
    if !info.in_sync {
        return Err(EvictOutcome::Error(format!(
            "{} has changes that are not shared yet",
            path.display()
        )));
    }
    let handle = Handle::open(path, GENERIC_READ | GENERIC_WRITE)
        .map_err(|e| EvictOutcome::Error(e.to_string()))?;
    // SAFETY: `handle` is open for writing; the whole file is dehydrated (full hydration policy).
    let result = unsafe {
        CfDehydratePlaceholder(handle.0, 0, i64::MAX, CF_DEHYDRATE_FLAG_NONE, std::ptr::null_mut())
    };
    match result {
        // Reported as evicted only once the dehydrate is on the disk: the daemon publishes the
        // newer version on that report.
        r if r >= 0 => flush_state(&handle).map_err(EvictOutcome::Error),
        ERROR_CLOUD_FILE_IN_USE | ERROR_SHARING_VIOLATION => Err(EvictOutcome::Busy),
        r => Err(EvictOutcome::Error(format!("CfDehydratePlaceholder: HRESULT {r:#x}"))),
    }
}

/// A path as the Windows file systems compare names: character by character through a simple
/// (one character to one character) upper case mapping, so that `\u{3c3}` and `\u{3c2}` are one
/// letter and `\u{df}` is not `SS`.
pub fn windows_name_key(path: &str) -> String {
    path.chars()
        .map(|c| {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(single), None) => single,
                _ => c,
            }
        })
        .collect()
}

/// The sync root path the daemon's name suggests: the display name, made usable as one folder
/// name, below `parent`; a different folder name when that one is taken by something that is not
/// already this root's.
pub fn choose_root_path(
    parent: &Path,
    display_name: &str,
    root_id: &[u8],
    taken: &HashSet<PathBuf>,
) -> PathBuf {
    let mut name: String = display_name
        .chars()
        .map(|c| if "\\/:*?\"<>|".contains(c) || (c as u32) < 0x20 { '_' } else { c })
        .collect();
    name = name.trim_matches(['.', ' ']).to_string();
    if name.is_empty() {
        name = "YadoriLink".to_string();
    }
    if is_reserved_device_name(&name) {
        name = format!("{name} folder");
    }
    // Windows folder names do not differ by case.
    let taken: HashSet<String> =
        taken.iter().map(|path| windows_name_key(&path.to_string_lossy())).collect();
    let occupied = |path: &Path| {
        taken.contains(&windows_name_key(&path.to_string_lossy()))
            || std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_some())
            || path.symlink_metadata().is_ok_and(|m| !m.is_dir())
    };
    let plain = parent.join(&name);
    if !occupied(&plain) {
        return plain;
    }
    // Every candidate is checked the same way: a folder that is not empty, or that belongs to
    // another root, is never taken over.
    let suffix: String = root_id.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let mut candidate = parent.join(format!("{name} ({suffix})"));
    let mut count = 2u32;
    while occupied(&candidate) {
        candidate = parent.join(format!("{name} ({suffix} {count})"));
        count += 1;
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfapi::{StageStep, STAGE_FAILPOINT};
    use yadorilink_fs_platform::durable_dir::{NameLedger, NoLedger};

    fn usn_of(path: &Path) -> Option<i64> {
        let handle = Handle::open(path, FILE_READ_ATTRIBUTES | GENERIC_READ).ok()?;
        file_usn(handle.0).ok().flatten()
    }

    fn record(version: u16, usn: i64, name_len: usize) -> Vec<u8> {
        let at = if version == 2 { 24 } else { 40 };
        let mut r = vec![0u8; at + 8 + 12 + name_len];
        r[4..6].copy_from_slice(&version.to_le_bytes());
        r[at..at + 8].copy_from_slice(&usn.to_le_bytes());
        r
    }

    #[test]
    fn a_long_name_grows_the_buffer_and_only_a_missing_journal_reads_as_none() {
        let long = record(2, 77, 1500);
        let mut sizes = vec![];
        let got = read_usn(|out| {
            sizes.push(out.len());
            if out.len() < long.len() {
                return Err(ERROR_MORE_DATA);
            }
            out[..long.len()].copy_from_slice(&long);
            Ok(long.len())
        });
        assert_eq!(got, Ok(Some(77)));
        assert!(sizes.len() > 1);
        let v3 = record(3, 5, 10);
        let got = read_usn(|out| {
            out[..v3.len()].copy_from_slice(&v3);
            Ok(v3.len())
        });
        assert_eq!(got, Ok(Some(5)));
        assert_eq!(read_usn(|_| Err(ERROR_JOURNAL_NOT_ACTIVE)), Ok(None));
        assert_eq!(read_usn(|_| Err(5)), Err(5), "access denied is not 'no journal'");
        assert_eq!(read_usn(|_| Err(ERROR_MORE_DATA)), Err(ERROR_MORE_DATA), "growth is bounded");
    }

    #[test]
    fn the_usn_guard_never_passes_a_copied_file_it_cannot_compare() {
        assert_eq!(usn_guard(None, Ok(None)), Ok(()), "nothing was copied: nothing to guard");
        assert_eq!(usn_guard(Some(0), Ok(Some(0))), Ok(()), "USN 0 is compared like any other");
        assert_eq!(usn_guard(Some(0), Ok(Some(9))), Err(AdoptError::Changed));
        for now in [Ok(None), Err(5)] {
            assert!(
                matches!(usn_guard(Some(4), now), Err(AdoptError::Failed(_))),
                "journal unavailable or unreadable must never mark in sync"
            );
        }
    }

    /// The same file object saved again after its bytes were read (same size, time restored): the
    /// stable file id is unchanged, only the USN tells. Neither the bind nor the discard may
    /// treat the old version as the file's.
    #[test]
    #[ignore = "real Cloud Files state and an NTFS change journal; run on a Windows machine"]
    fn a_file_saved_again_after_ingest_is_neither_marked_in_sync_nor_discarded() {
        use std::io::Write;
        let root = SyncRoot::new("resave");
        let a = root.0.join("a.txt");
        std::fs::write(&a, b"abc").unwrap();
        let id = file_id(&a).expect("an identity");
        let copied = usn_of(&a).expect("the volume has a change journal");
        let mtime = std::fs::metadata(&a).unwrap().modified().unwrap();
        let mut file = std::fs::OpenOptions::new().write(true).open(&a).unwrap();
        file.write_all(b"xyz").unwrap();
        file.set_modified(mtime).unwrap();
        drop(file);
        assert_eq!(file_id(&a), Some(id), "the same object");
        assert_ne!(usn_of(&a), Some(copied), "a save moves the USN");
        assert_eq!(bind_to_item(&a, b"item", id, Some(copied)), Err(AdoptError::Changed));
        assert!(placeholder_info(&a).is_none(), "marked/converted despite the re-save");
        assert_eq!(remove_object(&a, id, Some(copied)), Err(AdoptError::Changed));
        assert!(a.exists(), "a re-saved file must not be discarded");
        // With the current USN both go through.
        let now = usn_of(&a);
        bind_to_item(&a, b"item", id, now).unwrap();
        assert!(placeholder_info(&a).is_some_and(|i| i.in_sync));
        // A writer that is in keeps the bind out altogether.
        let writer = std::fs::OpenOptions::new().write(true).open(&a).unwrap();
        assert!(matches!(bind_to_item(&a, b"item", id, usn_of(&a)), Err(AdoptError::Failed(_))));
        drop(writer);
    }

    #[test]
    fn component_names_are_single_plain_names() {
        for good in ["a", "photo 1.jpg", "日本語.txt", ".hidden"] {
            assert!(valid_component(good), "{good}");
        }
        for bad in [
            "", ".", "..", "a/b", "a\\b", "c:", "a:b", "x.", "x ", "q?", "a\u{1}b", "a*b", "CON",
            "nul.txt", "Com1", "LPT9.log",
        ] {
            assert!(!valid_component(bad), "{bad:?}");
        }
    }

    /// A registered, connected sync root in a fresh temporary folder, unregistered and removed
    /// when dropped. Real Cloud Files state: the tests that use it are `#[ignore]`d and run on a
    /// Windows machine (`cargo test -- --ignored`).
    struct SyncRoot(PathBuf);

    impl SyncRoot {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("yl-ns-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            crate::cfapi::register_and_connect(&dir).expect("register and connect the sync root");
            Self(dir)
        }
    }

    impl Drop for SyncRoot {
        fn drop(&mut self) {
            let _ = crate::cfapi::unregister(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn names(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// E8 (windows-namespace-durability.md section 9): a placeholder made under a Stage name and
    /// moved to its name inside the sync root is the same placeholder: identity, size, in-sync and
    /// dehydrated state survive the move, and nothing is left under the Stage name.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_placeholder_published_from_its_stage_name_keeps_its_state() {
        let root = SyncRoot::new("file");
        create_item_placeholder(
            &NoLedger,
            &root.0,
            "a.txt",
            b"item-1",
            11,
            1_700_000_000_000_000_000,
            false,
        )
        .expect("create");
        assert_eq!(names(&root.0), ["a.txt"], "a Stage name was left behind");
        let info = placeholder_info(&root.0.join("a.txt")).expect("a placeholder at the name");
        assert_eq!(info.item_id.as_deref(), Some(&b"item-1"[..]));
        assert!(info.in_sync && info.dehydrated && !info.is_dir, "{info:?}");
        assert_eq!(info.size, 11);
    }

    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_directory_placeholder_published_from_its_stage_name_takes_children() {
        let root = SyncRoot::new("dir");
        create_item_placeholder(
            &NoLedger,
            &root.0,
            "d",
            b"item-d",
            0,
            1_700_000_000_000_000_000,
            true,
        )
        .expect("create the directory");
        let info = placeholder_info(&root.0.join("d")).expect("a placeholder at the name");
        assert_eq!(info.item_id.as_deref(), Some(&b"item-d"[..]));
        assert!(info.is_dir && info.in_sync, "{info:?}");
        create_item_placeholder(
            &NoLedger,
            &root.0.join("d"),
            "c.txt",
            b"item-c",
            3,
            1_700_000_000_000_000_000,
            false,
        )
        .expect("a child of the moved directory placeholder");
        assert_eq!(names(&root.0.join("d")), ["c.txt"]);
    }

    /// A name that is taken is never replaced by the publish, and the Stage placeholder does not
    /// outlive the failed attempt.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_taken_name_fails_the_create_and_leaves_no_stage_placeholder() {
        let root = SyncRoot::new("taken");
        std::fs::write(root.0.join("a.txt"), b"mine").unwrap();
        let error = create_item_placeholder(&NoLedger, &root.0, "a.txt", b"item-1", 11, 0, false)
            .expect_err("the user's file holds the name");
        // Made under a Stage name and refused at the publish; a direct create would be refused by
        // CfCreatePlaceholders itself.
        assert!(error.starts_with("publishing the placeholder"), "{error}");
        assert_eq!(names(&root.0), ["a.txt"]);
        assert_eq!(std::fs::read(root.0.join("a.txt")).unwrap(), b"mine");
    }

    /// Stage placeholders left by a crash between the create and the move are placeholders of an
    /// item (by identity) that no name asks for: the next walk removes them like any stale one.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_stage_placeholder_left_by_a_crash_is_removed_as_stale() {
        let root = SyncRoot::new("leftover");
        let stage = root.0.join(".yadorilink-v1-stage.crashed-1");
        crate::cfapi::create_item_placeholder_at(
            &root.0,
            ".yadorilink-v1-stage.crashed-1",
            b"item-1",
            5,
            0,
            false,
        )
        .expect("a placeholder under a Stage name");
        assert!(placeholder_info(&stage).is_some());
        remove_if_stale(&stage, None);
        assert!(names(&root.0).is_empty(), "{:?}", names(&root.0));
    }

    /// What a rename does to the in-sync bit (E8): the move onto a name is a rename the driver
    /// tracks, so the bit is cleared, and `mark_in_sync` sets it again.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_rename_clears_the_in_sync_bit_and_mark_in_sync_sets_it() {
        let root = SyncRoot::new("insync");
        crate::cfapi::create_item_placeholder_at(&root.0, "stage", b"item-1", 4, 0, false).unwrap();
        assert!(placeholder_info(&root.0.join("stage")).unwrap().in_sync);
        std::fs::rename(root.0.join("stage"), root.0.join("a.txt")).unwrap();
        let renamed = placeholder_info(&root.0.join("a.txt")).unwrap();
        assert!(!renamed.in_sync && renamed.dehydrated, "{renamed:?}");
        mark_in_sync(&root.0.join("a.txt")).unwrap();
        assert!(placeholder_info(&root.0.join("a.txt")).unwrap().in_sync);
    }

    /// The daemon's namespace as a fixed tree: parent item id -> children.
    struct FakeSource(HashMap<Vec<u8>, Vec<ProviderItem>>);

    impl NamespaceSource for FakeSource {
        fn children(&self, _root_id: &[u8], parent_item: &[u8]) -> Option<Vec<ProviderItem>> {
            Some(self.0.get(parent_item).cloned().unwrap_or_default())
        }
    }

    fn provider_item(
        id: &[u8],
        parent: &[u8],
        name: &str,
        directory: bool,
        size: u64,
    ) -> ProviderItem {
        ProviderItem {
            item_id: id.to_vec(),
            parent_item_id: parent.to_vec(),
            name: name.to_string(),
            entry_kind: if directory { EntryKind::Directory } else { EntryKind::File } as i32,
            size,
            mtime_unix_nanos: MTIME,
            content_version: vec![7; 40],
            ..Default::default()
        }
    }

    const MTIME: i64 = 1_700_000_000_000_000_000;

    /// The Stage ledger of a test sync root: beside the root, never inside the user's tree.
    fn ledger_of(root: &Path) -> StageLedger {
        StageLedger::at(root.with_extension("stage-ledger"))
    }

    fn records(root: &Path) -> usize {
        std::fs::read_dir(root.with_extension("stage-ledger"))
            .map(|entries| entries.flatten().count())
            .unwrap_or(0)
    }

    fn walk(root: &Path, source: &FakeSource, previous: &ShownItems) -> Option<ShownItems> {
        sync_namespace_from(source, &ledger_of(root), b"root", root, previous, &HashSet::new())
    }

    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_walk_publishes_the_namespace_through_stage_names_and_shows_what_it_made() {
        let root = SyncRoot::new("walk-publish");
        let source = FakeSource(HashMap::from([
            (
                vec![],
                vec![
                    provider_item(b"d", b"", "docs", true, 0),
                    provider_item(b"f", b"", "a.txt", false, 11),
                ],
            ),
            (b"d".to_vec(), vec![provider_item(b"c", b"d", "c.txt", false, 3)]),
        ]));
        let shown = walk(&root.0, &source, &ShownItems::new()).expect("a confirmed walk");
        assert_eq!(shown.len(), 3);
        assert_eq!(names(&root.0), ["a.txt", "docs"]);
        assert_eq!(names(&root.0.join("docs")), ["c.txt"]);
        for (path, id) in [("a.txt", &b"f"[..]), ("docs", b"d"), ("docs\\c.txt", b"c")] {
            let info = placeholder_info(&root.0.join(path)).unwrap_or_else(|| panic!("{path}"));
            assert_eq!(info.item_id.as_deref(), Some(id));
            assert!(info.in_sync, "{path} was shown out of sync");
        }
    }

    /// A retry-protected folder is left alone, but what is inside it is still walked: convergence
    /// must not stop below a folder whose rename is waiting to be reported.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_walk_descends_into_a_protected_folder_without_touching_the_folder() {
        let root = SyncRoot::new("walk-protected");
        crate::cfapi::create_item_placeholder_at(&root.0, "docs", b"d", 0, MTIME, true).unwrap();
        let source = FakeSource(HashMap::from([
            (vec![], vec![provider_item(b"d", b"", "docs", true, 0)]),
            (b"d".to_vec(), vec![provider_item(b"c", b"d", "c.txt", false, 3)]),
        ]));
        let before = placeholder_info(&root.0.join("docs")).unwrap();
        let protected = HashSet::from([root.0.join("docs").to_string_lossy().to_lowercase()]);
        let shown = sync_namespace_from(
            &source,
            &ledger_of(&root.0),
            b"root",
            &root.0,
            &ShownItems::new(),
            &protected,
        )
        .expect("a confirmed walk");
        let after = placeholder_info(&root.0.join("docs")).unwrap();
        assert_eq!((after.item_id, after.in_sync), (before.item_id, before.in_sync));
        assert_eq!(names(&root.0.join("docs")), ["c.txt"], "the walk stopped at the folder");
        assert!(shown.contains_key(&b"c"[..]));
    }

    /// Another folder moved onto the name of a protected one is not the daemon's folder: its
    /// content is not walked as that folder's.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_walk_does_not_descend_into_a_protected_folder_that_is_another_folder() {
        let root = SyncRoot::new("walk-protected-other");
        std::fs::create_dir(root.0.join("docs")).unwrap();
        let source = FakeSource(HashMap::from([
            (vec![], vec![provider_item(b"d", b"", "docs", true, 0)]),
            (b"d".to_vec(), vec![provider_item(b"c", b"d", "c.txt", false, 3)]),
        ]));
        let protected = HashSet::from([root.0.join("docs").to_string_lossy().to_lowercase()]);
        sync_namespace_from(
            &source,
            &ledger_of(&root.0),
            b"root",
            &root.0,
            &ShownItems::new(),
            &protected,
        );
        assert!(names(&root.0.join("docs")).is_empty(), "walked into someone else's folder");
    }

    /// The identity a request journals is the one a rename and the conversion to a placeholder
    /// keep, and the effects refuse any other object at the path.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn the_file_identity_survives_binding_and_a_rename_and_guards_the_effects() {
        let root = SyncRoot::new("file-id");
        let a = root.0.join("a.txt");
        std::fs::write(&a, b"abc").unwrap();
        let id = file_id(&a).expect("an identity");
        assert!(
            bind_to_item(&a, b"item", id.wrapping_add(1), None).is_err(),
            "bound another object"
        );
        assert!(placeholder_info(&a).is_none());
        bind_to_item(&a, b"item", id, None).unwrap();
        assert_eq!(file_id(&a), Some(id), "the conversion changed the identity");
        let b = root.0.join("b.txt");
        std::fs::rename(&a, &b).unwrap();
        assert_eq!(file_id(&b), Some(id), "a rename changed the identity");
        assert!(remove_object(&b, id.wrapping_add(1), None).is_err());
        assert!(b.exists(), "removed another object");
        remove_object(&b, id, None).unwrap();
        assert!(!b.exists());
        let folder = root.0.join("d");
        std::fs::create_dir(&folder).unwrap();
        let folder_id = file_id(&folder).expect("a folder identity");
        bind_to_item(&folder, b"dir", folder_id, None).unwrap();
        assert_eq!(file_id(&folder), Some(folder_id));
    }

    /// The Stage step killed at `point`, as a crashed process leaves it.
    fn killed_at(point: StageStep, root: &Path, name: &str, item: &[u8]) {
        STAGE_FAILPOINT.with(|armed| armed.set(Some(point)));
        let result = create_item_placeholder(&ledger_of(root), root, name, item, 5, MTIME, false);
        STAGE_FAILPOINT.with(|armed| armed.set(None));
        assert!(result.is_err_and(|e| e.starts_with("killed at")), "the failpoint did not fire");
    }

    /// Killed after the record and before the placeholder exists: only the record remains, and
    /// the recovery drops it on finding the path absent. Needs no Cloud Files state.
    #[test]
    fn a_kill_after_the_record_leaves_only_a_record_the_recovery_drops() {
        let dir = std::env::temp_dir().join(format!("yl-ns-rec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        killed_at(StageStep::Recorded, &dir, "a.txt", b"f");
        assert_eq!(records(&dir), 1);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "no Stage name in the tree");
        let ledger = ledger_of(&dir);
        let recovery = ledger.recover(&|_| true);
        assert_eq!((recovery.dropped, recovery.removed.len()), (1, 0));
        assert_eq!(records(&dir), 0);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(dir.with_extension("stage-ledger"));
    }

    /// Killed between the create and the move: the recorded Stage placeholder is retired by the
    /// next walk (by its record), the record goes once the path is found absent, and the walk
    /// then creates the item under its name.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_walk_retires_the_recorded_stage_placeholder_a_kill_after_the_create_left() {
        let root = SyncRoot::new("walk-leftover");
        killed_at(StageStep::Created, &root.0, "a.txt", b"f");
        assert_eq!(records(&root.0), 1);
        assert_eq!(names(&root.0).len(), 1, "the Stage placeholder exists");
        let source = FakeSource(HashMap::from([(
            vec![],
            vec![provider_item(b"f", b"", "a.txt", false, 5)],
        )]));
        let shown = walk(&root.0, &source, &ShownItems::new()).expect("a confirmed walk");
        assert_eq!(names(&root.0), ["a.txt"], "the Stage placeholder was left");
        assert!(shown.contains_key(&b"f"[..]));
        // The removal is not what drops the record; the next recovery finds the path absent.
        assert_eq!(records(&root.0), 1);
        walk(&root.0, &source, &shown).expect("a confirmed walk");
        assert_eq!(records(&root.0), 0);
    }

    /// An entry that merely looks like a Stage name, with no record, is not the recovery's: a
    /// plain file is never removed, and a placeholder is only a stale item like any other.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn the_recovery_touches_only_recorded_paths() {
        let root = SyncRoot::new("recover-exact");
        let lookalike = root.0.join(".yadorilink-v1-stage.1-2-3");
        std::fs::write(&lookalike, b"mine").unwrap();
        let ledger = ledger_of(&root.0);
        ledger.recover(&|path| placeholder_info(path).is_some_and(|i| i.item_id.is_some()));
        assert!(lookalike.exists(), "an unrecorded Stage-shaped file was removed");
        // Recorded but not an item placeholder: left, record kept.
        ledger.record(&lookalike).unwrap();
        let recovery =
            ledger.recover(&|path| placeholder_info(path).is_some_and(|i| i.item_id.is_some()));
        assert_eq!(recovery.kept, std::slice::from_ref(&lookalike));
        assert!(lookalike.exists());
        assert_eq!(records(&root.0), 1);
    }

    /// A normal create leaves neither a Stage name nor a record.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_create_that_finishes_leaves_no_record() {
        let root = SyncRoot::new("create-clean");
        create_item_placeholder(&ledger_of(&root.0), &root.0, "a.txt", b"f", 5, MTIME, false)
            .expect("create");
        assert_eq!(names(&root.0), ["a.txt"]);
        assert_eq!(records(&root.0), 0);
    }

    /// Killed after the durable move: the placeholder is at its name (not in sync), the record
    /// names a Stage path that is absent, and the walk drops the record and marks the item.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_kill_after_the_move_leaves_a_record_of_an_absent_stage() {
        let root = SyncRoot::new("kill-after-move");
        killed_at(StageStep::Moved, &root.0, "a.txt", b"f");
        assert_eq!(names(&root.0), ["a.txt"]);
        assert_eq!(records(&root.0), 1);
        let source = FakeSource(HashMap::from([(
            vec![],
            vec![provider_item(b"f", b"", "a.txt", false, 5)],
        )]));
        walk(&root.0, &source, &ShownItems::new()).expect("a confirmed walk");
        assert_eq!(records(&root.0), 0);
        assert!(placeholder_info(&root.0.join("a.txt")).unwrap().in_sync);
    }

    /// A refused publish removes the Stage placeholder but keeps its record, which the next
    /// recovery drops once it finds the path absent.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_refused_publish_keeps_its_record_until_the_path_is_seen_absent() {
        let root = SyncRoot::new("create-taken");
        std::fs::write(root.0.join("a.txt"), b"mine").unwrap();
        let ledger = ledger_of(&root.0);
        create_item_placeholder(&ledger, &root.0, "a.txt", b"f", 5, MTIME, false)
            .expect_err("the name is taken");
        assert_eq!(names(&root.0), ["a.txt"]);
        assert_eq!(records(&root.0), 1);
        let recovery = ledger.recover(&|_| true);
        assert_eq!((recovery.dropped, recovery.removed.len()), (1, 0));
        assert_eq!(records(&root.0), 0);
    }

    /// A crash between the move onto the name and the in-sync mark leaves a dehydrated placeholder
    /// of exactly the wanted item, not in sync, with the daemon's size and time: marked by the walk.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_walk_marks_in_sync_a_published_placeholder_whose_mark_never_happened() {
        let root = SyncRoot::new("walk-mark");
        crate::cfapi::create_item_placeholder_at(&root.0, "stage", b"f", 5, MTIME, false).unwrap();
        std::fs::rename(root.0.join("stage"), root.0.join("a.txt")).unwrap();
        assert!(!placeholder_info(&root.0.join("a.txt")).unwrap().in_sync);
        let source = FakeSource(HashMap::from([(
            vec![],
            vec![provider_item(b"f", b"", "a.txt", false, 5)],
        )]));
        walk(&root.0, &source, &ShownItems::new()).expect("a confirmed walk");
        assert!(placeholder_info(&root.0.join("a.txt")).unwrap().in_sync);
    }

    /// A power loss may return a dehydrate that was acknowledged: the placeholder is hydrated
    /// again with the bytes of the older version, in sync. A hydrated in-sync placeholder is what a
    /// converted plain file is, so that is the state built here. The walk repairs it as a missed
    /// eviction: the old bytes are dropped and the daemon's size and time are set.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_walk_repairs_a_hydrated_placeholder_of_an_older_version_a_lost_dehydrate_left() {
        let root = SyncRoot::new("lost-dehydrate");
        let a = root.0.join("a.txt");
        std::fs::write(&a, b"old").unwrap();
        let id = file_id(&a).expect("an identity");
        bind_to_item(&a, b"f", id, None).unwrap();
        let before = placeholder_info(&a).unwrap();
        assert!(before.in_sync && !before.dehydrated && before.size == 3, "{before:?}");
        let source = FakeSource(HashMap::from([(
            vec![],
            vec![provider_item(b"f", b"", "a.txt", false, 5)],
        )]));
        walk(&root.0, &source, &ShownItems::new()).expect("a confirmed walk");
        let after = placeholder_info(&a).unwrap();
        assert!(after.in_sync && after.dehydrated, "{after:?}");
        assert_eq!(after.size, 5);
        assert_eq!(after.mtime_ticks, unix_nanos_to_ticks(MTIME));
        assert_eq!(after.item_id.as_deref(), Some(&b"f"[..]));
    }

    /// An eviction is reported as done only once the dehydrate is on the disk: when that cannot be
    /// shown, the report is an error, and the daemon does not publish the newer version.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn an_eviction_whose_dehydrate_cannot_be_flushed_is_an_error_not_evicted() {
        let root = SyncRoot::new("evict-flush");
        let a = root.0.join("a.txt");
        std::fs::write(&a, b"old").unwrap();
        let id = file_id(&a).expect("an identity");
        bind_to_item(&a, b"f", id, None).unwrap();
        FLUSH_FAILS.with(|f| f.set(true));
        let failed = evict(&a, b"f");
        FLUSH_FAILS.with(|f| f.set(false));
        assert!(matches!(failed, Err(EvictOutcome::Error(_))), "{failed:?}");
        // With a working flush the eviction is Ok.
        let b = root.0.join("b.txt");
        std::fs::write(&b, b"old").unwrap();
        bind_to_item(&b, b"g", file_id(&b).unwrap(), None).unwrap();
        assert_eq!(evict(&b, b"g"), Ok(()));
        assert!(placeholder_info(&b).unwrap().dehydrated);
    }

    /// The daemon takes an eviction as a hint, so the order that matters is kept by the repair
    /// itself: the newer version's size and time are set only after the dehydrate is on the disk.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_placeholder_is_not_given_the_new_size_before_its_dehydrate_is_flushed() {
        let root = SyncRoot::new("update-flush");
        crate::cfapi::create_item_placeholder_at(&root.0, "a.txt", b"f", 4, MTIME, false).unwrap();
        let a = root.0.join("a.txt");
        let info = placeholder_info(&a).unwrap();
        let item = provider_item(b"f", b"", "a.txt", false, 5);
        FLUSH_FAILS.with(|f| f.set(true));
        let failed = update_placeholder(&a, &info, &item);
        FLUSH_FAILS.with(|f| f.set(false));
        assert!(failed.is_err(), "{failed:?}");
        assert_eq!(placeholder_info(&a).unwrap().size, 4, "the new size was set");
        update_placeholder(&a, &info, &item).unwrap();
        assert_eq!(placeholder_info(&a).unwrap().size, 5);
    }

    /// The same for a revert: it is reported as done only once it is on the disk.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_revert_that_cannot_be_flushed_is_an_error() {
        let root = SyncRoot::new("revert-flush");
        let a = root.0.join("a.txt");
        std::fs::write(&a, b"abc").unwrap();
        bind_to_item(&a, b"f", file_id(&a).unwrap(), None).unwrap();
        FLUSH_FAILS.with(|f| f.set(true));
        let failed = revert_to_plain(&a);
        FLUSH_FAILS.with(|f| f.set(false));
        assert!(failed.is_err());
        // The revert itself happened; only the report is withheld.
        assert!(placeholder_info(&a).is_none());
        let b = root.0.join("b.txt");
        std::fs::write(&b, b"abc").unwrap();
        bind_to_item(&b, b"g", file_id(&b).unwrap(), None).unwrap();
        revert_to_plain(&b).unwrap();
        assert!(placeholder_info(&b).is_none());
    }

    /// The same state after the user changed the time of the dehydrated placeholder is the user's
    /// change, not an interrupted publish: the walk leaves it for the watcher to report.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_walk_does_not_mark_in_sync_a_placeholder_whose_time_the_user_changed() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = SyncRoot::new("walk-touched");
        crate::cfapi::create_item_placeholder_at(&root.0, "a.txt", b"f", 5, MTIME, false).unwrap();
        let file = std::fs::OpenOptions::new()
            .access_mode(0x100) // FILE_WRITE_ATTRIBUTES: no data access, nothing is fetched
            .custom_flags(0x0020_0000) // FILE_FLAG_OPEN_REPARSE_POINT
            .open(root.0.join("a.txt"))
            .unwrap();
        file.set_modified(std::time::SystemTime::now()).unwrap();
        drop(file);
        let touched = placeholder_info(&root.0.join("a.txt")).unwrap();
        assert!(!touched.in_sync && touched.dehydrated, "{touched:?}");
        let source = FakeSource(HashMap::from([(
            vec![],
            vec![provider_item(b"f", b"", "a.txt", false, 5)],
        )]));
        walk(&root.0, &source, &ShownItems::new()).expect("a confirmed walk");
        assert_eq!(
            placeholder_info(&root.0.join("a.txt")).unwrap(),
            touched,
            "the walk changed it"
        );
    }

    /// After a restart the host looks for an item that is no longer at its shown path. A Stage
    /// placeholder of that item (a rename's publish a crash interrupted) is not where the user put
    /// it, and finding it there would report a rename to a reserved name.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_search_for_an_item_skips_its_stage_placeholder() {
        use crate::provider_authoring::{Local, Located, WindowsLocal};
        let root = SyncRoot::new("locate");
        let local = WindowsLocal { ingest_dir: root.0.join("unused") };
        let stage = ".yadorilink-v1-stage.crashed-1";
        crate::cfapi::create_item_placeholder_at(&root.0, stage, b"f", 5, MTIME, false).unwrap();
        crate::cfapi::create_item_placeholder_at(&root.0, "b.txt", b"g", 5, MTIME, false).unwrap();
        assert!(matches!(local.locate(&root.0, b"f"), Located::Absent));
        assert!(
            matches!(local.locate(&root.0, b"g"), Located::Found(p) if p == root.0.join("b.txt"))
        );
    }

    #[test]
    fn a_root_path_is_a_usable_folder_name_that_never_reuses_a_foreign_folder() {
        let parent = std::env::temp_dir().join(format!("yl-roots-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        let taken = HashSet::new();
        assert_eq!(
            choose_root_path(&parent, "NUL", &[1, 2, 3, 4, 5], &taken),
            parent.join("NUL folder")
        );
        assert_eq!(
            choose_root_path(&parent, "My: Photos?", &[1, 2, 3, 4, 5], &taken),
            parent.join("My_ Photos_")
        );
        std::fs::create_dir_all(parent.join("Photos")).unwrap();
        std::fs::write(parent.join("Photos").join("mine.txt"), b"x").unwrap();
        assert_eq!(
            choose_root_path(&parent, "Photos", &[0xab, 0xcd, 0xef, 0x01, 9], &taken),
            parent.join("Photos (abcdef01)")
        );
        std::fs::create_dir_all(parent.join("Photos (abcdef01)")).unwrap();
        std::fs::write(parent.join("Photos (abcdef01)").join("x"), b"y").unwrap();
        assert_eq!(
            choose_root_path(&parent, "Photos", &[0xab, 0xcd, 0xef, 0x01, 9], &taken),
            parent.join("Photos (abcdef01 2)"),
            "a taken fallback folder was reused"
        );
        let _ = std::fs::remove_dir_all(&parent);
    }
}
