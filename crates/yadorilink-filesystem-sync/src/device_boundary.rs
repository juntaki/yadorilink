//! Device (mount) boundary rule for everything that feeds capture.
//!
//! A sync root never indexes across a filesystem boundary: a nested mount
//! under the root is not part of the replica. If it were, unmounting it would
//! leave an empty mountpoint and the offline-tombstone logic would sign
//! group-wide Deletes for the whole former subtree.
//!
//! Policy: walks never descend into a directory whose device differs from the
//! root's. On unix the mountpoint directory itself is skipped as well (it is
//! `foreign`); on Windows walkdir's `same_file_system` yields it as an empty
//! directory and does not descend. Either way nothing beneath it is captured,
//! and rows already indexed beneath a foreign device are never tombstoned
//! (see [`path_crosses_device_boundary`]).

use std::path::Path;

/// True if `dir` is on a different device than `root` (unix: `st_dev`).
/// Non-unix walks rely on walkdir's `same_file_system(true)` instead.
pub fn is_foreign_device_dir(root: &Path, dir: &Path) -> bool {
    #[cfg(any(test, feature = "test-support"))]
    if seam::is_foreign(dir) {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(r), Ok(d)) = (std::fs::metadata(root), std::fs::symlink_metadata(dir)) {
            return r.dev() != d.dev();
        }
    }
    let _ = root;
    false
}

/// The volume the sync root itself is on, as a stable string (`unix:<st_dev>`
/// or `windows:<volume serial>`), or `None` when it cannot be observed.
///
/// Persisted per link and compared before any tombstone is authored: if the
/// root's volume is not the one the index was built from (a swapped volume,
/// an unmounted root leaving an empty mountpoint), absence on disk is not
/// delete evidence. One predicate for every platform.
pub fn root_volume_identity(root: &Path) -> Option<String> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(over) = seam::root_identity_override(root) {
        return over;
    }
    use yadorilink_fs_platform::fs_identity::VolumeIdentity;
    match yadorilink_fs_platform::fs_capabilities::observe_volume_identity(root).ok()? {
        VolumeIdentity::Unix { device_id } => Some(format!("unix:{device_id}")),
        VolumeIdentity::Windows { volume_serial_number } => {
            Some(format!("windows:{volume_serial_number}"))
        }
    }
}

/// True if `rel_path` (root-relative) is, or lies under, a directory that is
/// currently on another device than `root`. Such a path is not ours to judge:
/// its absence from a walk is not delete evidence.
pub fn path_crosses_device_boundary(root: &Path, rel_path: &str) -> bool {
    let mut cur = root.to_path_buf();
    for component in Path::new(rel_path).components() {
        cur.push(component);
        if is_foreign_device_dir(root, &cur) {
            return true;
        }
    }
    false
}

/// Test-only seam simulating a device boundary without a real mount.
#[cfg(any(test, feature = "test-support"))]
pub mod seam {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static FOREIGN: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    /// Marks `dir` (and everything under it) as another device.
    pub fn mark_foreign(dir: &Path) {
        FOREIGN.lock().unwrap().push(dir.to_path_buf());
    }

    pub fn clear(dir: &Path) {
        FOREIGN.lock().unwrap().retain(|p| p != dir);
    }

    static ROOT_IDENTITY: Mutex<Vec<(PathBuf, Option<String>)>> = Mutex::new(Vec::new());

    /// Makes `root` report `identity` (`None`: unobservable) as its volume.
    pub fn set_root_identity(root: &Path, identity: Option<&str>) {
        let mut all = ROOT_IDENTITY.lock().unwrap();
        all.retain(|(p, _)| p != root);
        all.push((root.to_path_buf(), identity.map(str::to_owned)));
    }

    pub fn clear_root_identity(root: &Path) {
        ROOT_IDENTITY.lock().unwrap().retain(|(p, _)| p != root);
    }

    pub(super) fn root_identity_override(root: &Path) -> Option<Option<String>> {
        ROOT_IDENTITY.lock().unwrap().iter().find(|(p, _)| p == root).map(|(_, v)| v.clone())
    }

    pub(super) fn is_foreign(dir: &Path) -> bool {
        FOREIGN.lock().unwrap().iter().any(|p| dir.starts_with(p))
    }
}
