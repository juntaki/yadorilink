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
    let known = VERDICTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find_map(|(v, c)| (*v == volume).then_some(*c));
    if let Some(verdict) = known {
        return verdict;
    }
    let verdict = probe(dir);
    if verdict != Capability::Unknown {
        VERDICTS.lock().unwrap_or_else(|p| p.into_inner()).push((volume, verdict));
    }
    verdict
}

/// Identifies the volume under `dir`: the device number on Unix, the volume
/// serial number on Windows.
pub(super) fn volume_key(dir: &Path) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(std::fs::metadata(dir)?.dev())
    }
    #[cfg(windows)]
    {
        windows::volume_serial(dir)
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

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetDriveTypeW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
        GetVolumeInformationByHandleW, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        VOLUME_NAME_DOS,
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

    pub(super) fn volume_serial(dir: &Path) -> io::Result<u64> {
        let handle = open_dir(dir)?;
        let raw = handle.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid out-value.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `raw` is open for the call and `info` is writable.
        if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(u64::from(info.dwVolumeSerialNumber))
    }

    /// `(file system name, is a local fixed disk)` of the volume under `dir`.
    pub(super) fn volume_of(dir: &Path) -> io::Result<(String, bool)> {
        let handle = open_dir(dir)?;
        let raw = handle.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;

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

        let mut path = [0u16; 1024];
        // SAFETY: as above; `path` is writable for its length.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                raw,
                path.as_mut_ptr(),
                path.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if len == 0 || len >= path.len() {
            return Err(io::Error::last_os_error());
        }
        let final_path = String::from_utf16_lossy(&path[..len]);
        Ok((
            name,
            final_path_is_on_fixed_drive(&final_path, |root| {
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
}
