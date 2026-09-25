//! The crate's single boundary for the filesystem primitives that publish
//! or remove objects: removing a path, atomically replacing a path,
//! publishing a path only if it is absent, and making a directory's own
//! entries durable.
//!
//! These live here rather than inside whichever module happened to need
//! them first so that an audit of "where does this crate unlink, rename,
//! or issue a directory barrier?" has exactly one place to look. Moved out
//! of the deleted loose-file block backend, unchanged.

use std::fs;
use std::path::Path;

use crate::error::StorageError;

/// Single crate-wide boundary for removing a filesystem object. Block-store
/// segment retirement and materialization cleanup both pass through here so
/// audits see every physical removal at one capability seam.
pub(crate) fn remove_path(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)
}

/// What [`remove_empty_dir`] found at its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyDirectoryRemoval {
    /// The directory was empty and is gone.
    Removed,
    /// Nothing was at the path.
    Absent,
    /// The directory still holds entries. Nothing was removed.
    NotEmpty,
    /// Something other than a directory is at the path (a symlink to a
    /// directory included). Nothing was removed.
    NotADirectory,
}

/// Removes the directory at `path` only if it is empty: one non-recursive
/// `rmdir`. The only way this crate removes a directory. There is no
/// recursive counterpart on purpose: a directory's contents are removed
/// entry by entry by whoever knows each one (a replicated delete), and
/// anything left is something this device does not know about -- a
/// user's untracked file, an ignored `.git`, an OS's `.DS_Store` -- which
/// is never deleted on anyone's behalf.
pub fn remove_empty_dir(path: &Path) -> Result<EmptyDirectoryRemoval, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Ok(EmptyDirectoryRemoval::NotADirectory),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(EmptyDirectoryRemoval::Absent)
        }
        Err(e) => return Err(e.into()),
    }
    match fs::remove_dir(path) {
        Ok(()) => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                if let Err(error) = sync_directory(parent) {
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "directory was removed but its parent directory could not be synced"
                    );
                }
            }
            Ok(EmptyDirectoryRemoval::Removed)
        }
        Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
            Ok(EmptyDirectoryRemoval::NotEmpty)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(EmptyDirectoryRemoval::Absent),
        // Replaced by something that is not a directory since the check
        // above (`ENOTDIR`): not ours to remove.
        Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => {
            Ok(EmptyDirectoryRemoval::NotADirectory)
        }
        Err(e) => Err(e.into()),
    }
}

/// Single crate-wide boundary for atomically replacing a filesystem path.
/// Callers remain responsible for their operation-specific durability and
/// containment checks.
pub(crate) fn rename_path(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

/// Single crate-wide boundary for publishing `source` at `destination`
/// only if nothing is there: a hard link never replaces an existing entry,
/// and fails with `AlreadyExists` instead.
pub(crate) fn link_if_absent(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::hard_link(source, destination)
}

/// Makes `path`'s own directory entries durable. A file that has been
/// written and fsynced is still unreachable after a crash until the
/// directory entry naming it has itself reached disk, so every path that
/// creates a file it will later claim to be durable owes one of these.
#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> Result<(), StorageError> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn sync_directory(path: &Path) -> Result<(), StorageError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is NUL-terminated and remains alive for the call. The
    // returned handle is checked and closed on every successful-open path.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(StorageError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: `handle` is a valid directory handle returned by CreateFileW.
    let flushed = unsafe { FlushFileBuffers(handle) };
    let flush_error = (flushed == 0).then(std::io::Error::last_os_error);
    // SAFETY: this function owns the valid handle and closes it exactly once.
    unsafe { CloseHandle(handle) };
    if let Some(error) = flush_error {
        return Err(StorageError::Io(error));
    }
    Ok(())
}
