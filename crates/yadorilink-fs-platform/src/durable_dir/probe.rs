//! The per-volume probe: does the set of shapes in [`super`] work on the volume
//! `dir` lives on? The answer is the authority; the file system name is only a
//! precondition (Windows: a local fixed NTFS volume).

use std::io;
use std::path::Path;
use std::sync::Mutex;

use super::{DiscardOutcome, DurableNamespace, NoLedger, NsError, Replace};
use crate::fs_capabilities::Capability;

#[cfg(any(windows, test))]
const DRIVE_FIXED: u32 = 3;

const PROBE_LABEL: &str = "dir-durability";
/// A probe directory older than this is the residue of a probe that never
/// finished (a crash), not of one running now.
const STALE_AFTER_NANOS: u128 = 3_600_000_000_000;

/// Verdicts per volume, so the probe runs once per volume and process. A probe
/// that could not run (`Unknown`) is not kept.
static VERDICTS: Mutex<Vec<(u64, Capability)>> = Mutex::new(Vec::new());

pub(super) fn cached_verdict(dir: &Path) -> Capability {
    let Ok(volume) = volume_key(dir) else { return Capability::Unknown };
    verdict_for(volume, || probe(dir))
}

/// The cached verdict for `volume`, or `probe_now`'s, kept unless it is `Unknown`.
fn verdict_for(volume: u64, probe_now: impl FnOnce() -> Capability) -> Capability {
    let known = VERDICTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find_map(|(v, c)| (*v == volume).then_some(*c));
    if let Some(verdict) = known {
        return verdict;
    }
    let verdict = probe_now();
    if verdict != Capability::Unknown {
        VERDICTS.lock().unwrap_or_else(|p| p.into_inner()).push((volume, verdict));
    }
    verdict
}

/// A number for `key`, the same one every time and never shared with another key,
/// so a volume stays a plain `u64` to the callers.
#[cfg(any(windows, test))]
fn intern(key: String) -> u64 {
    static KEYS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut keys = KEYS.lock().unwrap_or_else(|p| p.into_inner());
    let at = keys.iter().position(|k| *k == key).unwrap_or_else(|| {
        keys.push(key);
        keys.len() - 1
    });
    at as u64
}

/// The identity of a Windows volume: its serial number alone is not unique (two
/// volumes may share one, and a verdict, or a same-volume check, must not carry
/// from one to the other), so the key adds the file system name and the volume
/// part of the final path by volume GUID (`Volume{guid}`, which also tells apart
/// volumes mounted in folders; a share gives `UNC\server\share`).
#[cfg(any(windows, test))]
fn windows_volume_key(serial: u32, fs_name: &str, volume_path: &str) -> String {
    let rest = volume_path.strip_prefix(r"\\?\").unwrap_or(volume_path);
    let volume_part = if rest.len() >= 4 && rest[..4].eq_ignore_ascii_case("UNC\\") {
        rest.splitn(4, '\\').take(3).collect::<Vec<_>>().join("\\")
    } else {
        rest.split('\\').next().unwrap_or(rest).to_owned()
    };
    format!("{serial:08x}|{}|{}", fs_name.to_ascii_lowercase(), volume_part.to_ascii_lowercase())
}

/// Identifies the volume under `dir`: the device number on Unix, on Windows
/// [`windows_volume_key`].
pub(super) fn volume_key(dir: &Path) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(std::fs::metadata(dir)?.dev())
    }
    #[cfg(windows)]
    {
        let d = windows::describe(dir)?;
        Ok(intern(windows_volume_key(d.serial, &d.fs_name, &d.volume_path)))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Runs the probe on `dir`'s volume now.
pub(super) fn probe(dir: &Path) -> Capability {
    #[cfg(windows)]
    {
        let Ok((fs_name, fixed)) = windows::volume_of(dir) else { return Capability::Unknown };
        if !fixed || !fs_name.eq_ignore_ascii_case("NTFS") {
            return Capability::Unsupported;
        }
    }
    sweep_stale(dir);
    let Ok(base) = crate::fs_capabilities::probe_artefact_name(PROBE_LABEL) else {
        return Capability::Unknown;
    };
    let work = dir.join(base);
    if std::fs::create_dir(&work).is_err() {
        return Capability::Unknown;
    }
    let verdict = super::quiet(|| shapes_work(&work));
    let _ = std::fs::remove_dir_all(&work);
    if verdict {
        Capability::Supported
    } else {
        Capability::Unsupported
    }
}

/// The five things the contract needs, on throwaway entries under `work`: a
/// published file, a refused second no-replace publish, a published directory,
/// a replacing publish and a discard.
fn shapes_work(work: &Path) -> bool {
    let ns = DurableNamespace::unchecked();
    let result = (|| -> Result<bool, NsError> {
        let (file, sub) = (work.join("f"), work.join("d"));
        ns.create_file(&file, Replace::No, &NoLedger, |f| io::Write::write_all(f, b"probe"))?;
        let refused = matches!(
            ns.create_file(&file, Replace::No, &NoLedger, |f| io::Write::write_all(f, b"again")),
            Err(NsError::AlreadyExists)
        );
        ns.create_dir(&sub, &NoLedger)?;
        ns.create_file(&file, Replace::Yes, &NoLedger, |f| io::Write::write_all(f, b"second"))?;
        let replaced = std::fs::read(&file).map_err(NsError::Io)? == b"second";
        let outcome = ns.discard(&file, &NoLedger)?.finish(&ns, &NoLedger);
        Ok(refused && replaced && outcome == DiscardOutcome::Removed)
    })();
    result.unwrap_or(false)
}

/// Removes this probe's own residue (reserved name, this label, old enough).
fn sweep_stale(dir: &Path) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some((crate::reserved_namespace::ArtefactKind::Probe, id)) =
            crate::reserved_namespace::parse_artefact_component(&name)
        else {
            continue;
        };
        // `<pid>-<nanos>-<counter>-<label>`
        let mut parts = id.splitn(4, '-');
        let (_pid, nanos, _counter, label) =
            (parts.next(), parts.next(), parts.next(), parts.next());
        let old = nanos
            .and_then(|n| n.parse::<u128>().ok())
            .is_some_and(|n| now.saturating_sub(n) > STALE_AFTER_NANOS);
        if label == Some(PROBE_LABEL) && old && entry.path().is_dir() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The verdict on `dir`'s volume without the cache and without the Windows
/// gate, for the evidence runs.
pub fn probe_directory_durability(dir: &Path) -> Capability {
    probe(dir)
}

/// `(file system name, is a local fixed disk)` of the volume that `dir` really
/// lives on, judged from a handle to the directory itself: a junction or
/// symbolic link in the path is followed to its target, so a path that starts on
/// `C:` but ends on a share is not mistaken for local. Windows only; evidence
/// tooling reports it next to the probe's verdict.
#[cfg(windows)]
pub fn local_volume_file_system(dir: &Path) -> io::Result<(String, bool)> {
    windows::volume_of(dir)
}

#[cfg(any(windows, test))]
/// `\\?\C:\dir` is on drive `C:`; `\\?\UNC\server\share` and a volume
/// without a drive letter are not accepted. `drive_type` maps a root such as
/// `C:\` to its Win32 drive type.
fn final_path_is_on_fixed_drive(final_path: &str, drive_type: impl Fn(&str) -> u32) -> bool {
    let Some(rest) = final_path.strip_prefix(r"\\?\") else { return false };
    let bytes = rest.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return false;
    }
    drive_type(&format!("{}:\\", &rest[..1])) == DRIVE_FIXED
}

/// The volume GUID path of the directory `dir`, for tests.
#[cfg(all(windows, test))]
pub(super) fn volume_guid_path_for_test(dir: &Path) -> String {
    windows::describe(dir).unwrap().volume_path
}

/// The Windows removal of [`super::remove_file_judged`]: the file is opened once (a final link is
/// the object, not followed), the verdict is asked about the directory its handle names by
/// volume GUID, and the file is deleted through that handle.
#[cfg(windows)]
pub(super) fn remove_file_through_handle(
    path: &Path,
    judge: impl FnOnce(&Path) -> bool,
) -> Result<(), super::JudgedRemoveError> {
    use super::JudgedRemoveError::{Io, Refused};
    let file = windows::open_for_delete(path).map_err(Io)?;
    judge_open_file(&file, judge)?;
    windows::delete_through(&file).map_err(Io)
}

/// Asks `judge` about the directory the open `file` lives in, named by volume GUID so it leads to
/// the volume of the object the handle is on, not to wherever a path spelling resolves now.
#[cfg(windows)]
pub(super) fn judge_open_file(
    file: &std::fs::File,
    judge: impl FnOnce(&Path) -> bool,
) -> Result<(), super::JudgedRemoveError> {
    use super::JudgedRemoveError::{Io, Refused};
    let seen = windows::describe_handle(file).map_err(Io)?;
    let named = std::path::PathBuf::from(&seen.volume_path);
    let parent = named.parent().ok_or_else(|| {
        Io(io::Error::new(io::ErrorKind::InvalidInput, "a file has a parent directory"))
    })?;
    let key = windows_volume_key(seen.serial, &seen.fs_name, &seen.volume_path);
    if !judge(parent) {
        return Err(Refused);
    }
    // The directory the verdict looked at must still be on the volume of the object: a swap
    // while the verdict ran is refused rather than trusted.
    let after = windows::describe(parent).map_err(Io)?;
    if windows_volume_key(after.serial, &after.fs_name, &after.volume_path) != key {
        return Err(Refused);
    }
    Ok(())
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, FileDispositionInfoEx, GetDriveTypeW, GetFileInformationByHandle,
        GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, SetFileInformationByHandle,
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        VOLUME_NAME_DOS, VOLUME_NAME_GUID,
    };

    /// A handle to the directory itself. Followed on purpose (no
    /// OPEN_REPARSE_POINT): the target is what counts.
    fn open_dir(dir: &Path) -> io::Result<std::fs::File> {
        let handle = std::fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)?;
        if !handle.metadata()?.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a directory"));
        }
        Ok(handle)
    }

    /// A handle to the file itself, for deleting through it. A final link is not followed.
    pub(super) fn open_for_delete(path: &Path) -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    /// Deletes the file `handle` is open on, as soon as the name is released (POSIX semantics
    /// where the file system has them, else on close).
    pub(super) fn delete_through(handle: &std::fs::File) -> io::Result<()> {
        let raw = handle.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        let ex = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        // SAFETY: `raw` is open for the call; `ex` is a live FILE_DISPOSITION_INFO_EX.
        let done = unsafe {
            SetFileInformationByHandle(
                raw,
                FileDispositionInfoEx,
                std::ptr::addr_of!(ex).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        };
        if done != 0 {
            return Ok(());
        }
        let ex_error = io::Error::last_os_error();
        let plain = FILE_DISPOSITION_INFO { DeleteFile: 1 };
        // SAFETY: as above, with a live FILE_DISPOSITION_INFO.
        let done = unsafe {
            SetFileInformationByHandle(
                raw,
                FileDispositionInfo,
                std::ptr::addr_of!(plain).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        if done != 0 {
            Ok(())
        } else {
            // The extended form's error says why, unless the plain one failed differently.
            let plain_error = io::Error::last_os_error();
            Err(if ex_error.raw_os_error() == Some(87) { plain_error } else { ex_error })
        }
    }

    pub(super) struct Described {
        pub serial: u32,
        pub fs_name: String,
        pub final_path: String,
        /// The final path by volume GUID, which names the volume even when it is
        /// mounted in a folder; the DOS path where the volume has no GUID (a share).
        pub volume_path: String,
    }

    /// Serial number, file system name and final path, all read from one handle to `dir`.
    pub(super) fn describe(dir: &Path) -> io::Result<Described> {
        describe_handle(&open_dir(dir)?)
    }

    /// [`describe`] for a handle that is already open.
    pub(super) fn describe_handle(handle: &std::fs::File) -> io::Result<Described> {
        let raw = handle.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;

        // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid out-value.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `raw` is open for the call and `info` is writable.
        if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut fs_name = [0u16; 64];
        // SAFETY: `raw` is open for the call; unused out-parameters are null and
        // `fs_name` is writable for its length.
        let ok = unsafe {
            GetVolumeInformationByHandleW(
                raw,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                fs_name.as_mut_ptr(),
                fs_name.len() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let end = fs_name.iter().position(|&c| c == 0).unwrap_or(fs_name.len());
        let name = std::ffi::OsString::from_wide(&fs_name[..end]).to_string_lossy().into_owned();

        let final_path_with = |flags| -> io::Result<String> {
            // A result longer than the buffer is reported by its needed length (with the
            // terminator): ask again with room for it rather than cut the path short.
            let mut path = vec![0u16; 1024];
            loop {
                // SAFETY: `raw` is open for the call; `path` is writable for its length.
                let len = unsafe {
                    GetFinalPathNameByHandleW(raw, path.as_mut_ptr(), path.len() as u32, flags)
                } as usize;
                if len == 0 {
                    return Err(io::Error::last_os_error());
                }
                if len < path.len() {
                    return Ok(String::from_utf16_lossy(&path[..len]));
                }
                path = vec![0u16; len + 1];
            }
        };
        // A volume mounted only in a folder has no DOS path; it is named by its GUID path
        // alone (and is not a drive-letter volume, which `volume_of` then reports).
        let guid = final_path_with(FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
        let dos = final_path_with(FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        let (final_path, volume_path) = match (dos, guid) {
            (Ok(dos), Ok(guid)) => (dos, guid),
            (Ok(dos), Err(_)) => (dos.clone(), dos),
            (Err(_), Ok(guid)) => (guid.clone(), guid),
            (Err(e), Err(_)) => return Err(e),
        };
        Ok(Described { serial: info.dwVolumeSerialNumber, fs_name: name, final_path, volume_path })
    }

    /// `(file system name, is a local fixed disk)` of the volume under `dir`.
    pub(super) fn volume_of(dir: &Path) -> io::Result<(String, bool)> {
        let d = describe(dir)?;
        Ok((
            d.fs_name,
            final_path_is_on_fixed_drive(&d.final_path, |root| {
                let wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
                // SAFETY: `wide` is NUL-terminated.
                unsafe { GetDriveTypeW(wide.as_ptr()) }
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_drive_letter_path_on_a_fixed_drive_is_local() {
        let fixed = |_: &str| DRIVE_FIXED;
        assert!(final_path_is_on_fixed_drive(r"\\?\C:\Users\x", fixed));
        assert!(!final_path_is_on_fixed_drive(r"\\?\UNC\server\share\x", fixed));
        assert!(!final_path_is_on_fixed_drive(r"\\?\Volume{1234}\x", fixed));
        assert!(!final_path_is_on_fixed_drive(r"C:\no\prefix", fixed));
        assert!(!final_path_is_on_fixed_drive(r"\\?\D:\x", |root| {
            assert_eq!(root, "D:\\");
            4 // DRIVE_REMOTE
        }));
    }

    #[test]
    fn volumes_sharing_a_serial_have_different_keys() {
        let ntfs_c = windows_volume_key(0x1234, "NTFS", r"\\?\C:\data");
        assert_ne!(ntfs_c, windows_volume_key(0x1234, "NTFS", r"\\?\D:\data"));
        assert_ne!(ntfs_c, windows_volume_key(0x1234, "FAT32", r"\\?\C:\data"));
        assert_ne!(
            windows_volume_key(0x1234, "NTFS", r"\\?\Volume{a}\x"),
            windows_volume_key(0x1234, "NTFS", r"\\?\Volume{b}\x")
        );
        assert_ne!(
            windows_volume_key(1, "NTFS", r"\\?\UNC\srv\one\x"),
            windows_volume_key(1, "NTFS", r"\\?\UNC\srv\two\x")
        );
        // The same volume reached through different directories is one key.
        assert_eq!(ntfs_c, windows_volume_key(0x1234, "ntfs", r"\\?\c:\other\dir"));
    }

    #[test]
    fn a_verdict_is_not_reused_for_another_volume() {
        let supported = intern(windows_volume_key(7, "NTFS", r"\\?\C:\a"));
        let other = intern(windows_volume_key(7, "NTFS", r"\\?\Volume{zz}\a"));
        assert_ne!(supported, other);
        assert_eq!(verdict_for(supported, || Capability::Supported), Capability::Supported);
        // Not probed again for the same volume ...
        assert_eq!(verdict_for(supported, || panic!("probed twice")), Capability::Supported);
        // ... but a different volume with the same serial gets its own probe.
        assert_eq!(verdict_for(other, || Capability::Unsupported), Capability::Unsupported);
    }

    #[test]
    fn a_directory_and_its_child_share_one_volume_key() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("child");
        std::fs::create_dir(&child).unwrap();
        assert_eq!(volume_key(dir.path()).unwrap(), volume_key(&child).unwrap());
    }
}
