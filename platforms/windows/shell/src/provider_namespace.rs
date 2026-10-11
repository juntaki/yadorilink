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
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use yadorilink_ipc_proto::shellipc::{EntryKind, ProviderItem};

use crate::cfapi::{create_item_placeholder, decode_item_identity};

/// `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` and `FILE_ATTRIBUTE_RECALL_ON_OPEN`: the attributes of
/// a placeholder whose content is not on the disk.
const RECALL_ATTRIBUTES: u32 = 0x0040_0000 | 0x0004_0000;

const ERROR_CLOUD_FILE_IN_USE: i32 = 0x8007_016Au32 as i32;
const ERROR_SHARING_VIOLATION: i32 = 0x8007_0020u32 as i32;

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    // Past MAX_PATH a raw wide-character call needs the verbatim form.
    yadorilink_fs_platform::long_path::for_win32(path).as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// An open handle, closed on drop.
struct Handle(HANDLE);

impl Handle {
    /// Opens `path` itself (a reparse point is not followed, and nothing is hydrated).
    fn open(path: &Path, access: u32) -> std::io::Result<Self> {
        let name = wide(path);
        // SAFETY: `name` is NUL-terminated.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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
    let mut shown = ShownItems::new();
    let mut complete = true;
    sync_directory(root_id, root_path, &[], &mut shown, &mut complete, previous, protected);
    complete.then_some(shown)
}

fn sync_directory(
    root_id: &[u8],
    directory: &Path,
    parent_item: &[u8],
    shown: &mut ShownItems,
    complete: &mut bool,
    previous: &ShownItems,
    protected: &HashSet<String>,
) {
    let Some(items) = crate::provider_client::enumerate_children(root_id, parent_item) else {
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
            // The user did something here that has not been reported yet: not touched.
            if let Some(old) = previous.get(&item.item_id) {
                shown.insert(item.item_id.clone(), old.clone());
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
            }
            Some(info) if info.item_id.as_deref() == Some(item.item_id.as_slice()) => {
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
            sync_directory(root_id, &path, &item.item_id, shown, complete, previous, protected);
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
            CF_UPDATE_FLAG_MARK_IN_SYNC,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result < 0 {
        return Err(format!("CfUpdatePlaceholder: HRESULT {result:#x}"));
    }
    Ok(())
}

/// Binds the file or folder at `path` to the daemon's item: a plain one becomes a placeholder
/// carrying the item id (its content stays on the disk, in sync), and a placeholder is marked in
/// sync (its identity is the item's already, and the daemon now holds what is on the disk).
pub fn bind_to_item(path: &Path, item_id: &[u8]) -> Result<(), String> {
    let handle = Handle::open(path, GENERIC_READ | GENERIC_WRITE).map_err(|e| e.to_string())?;
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
        return Err(format!("HRESULT {result:#x}"));
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
    Ok(())
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
        return Err(EvictOutcome::Error(format!("{} has changes that are not shared yet", path.display())));
    }
    let handle = Handle::open(path, GENERIC_READ | GENERIC_WRITE)
        .map_err(|e| EvictOutcome::Error(e.to_string()))?;
    // SAFETY: `handle` is open for writing; the whole file is dehydrated (full hydration policy).
    let result = unsafe {
        CfDehydratePlaceholder(handle.0, 0, i64::MAX, CF_DEHYDRATE_FLAG_NONE, std::ptr::null_mut())
    };
    match result {
        r if r >= 0 => Ok(()),
        ERROR_CLOUD_FILE_IN_USE | ERROR_SHARING_VIOLATION => Err(EvictOutcome::Busy),
        r => Err(EvictOutcome::Error(format!("CfDehydratePlaceholder: HRESULT {r:#x}"))),
    }
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
    let occupied = |path: &Path| {
        taken.contains(path)
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
