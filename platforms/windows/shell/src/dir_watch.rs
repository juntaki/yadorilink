//! A recursive directory watcher, used purely as a SIGNAL source.
//!
//! `ReadDirectoryChangesW` says that something happened at a path (created, changed, renamed,
//! removed); it is not trusted to say what. Whoever receives the signal looks at the path and at
//! the provider state and decides. When the watcher cannot keep up (the buffer overflowed, the
//! driver returned nothing) it says so with [`Signal::Overflow`] and the receiver must look at
//! everything.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::CancelIoEx;

/// What the watcher reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// These paths (absolute) were touched.
    Paths(Vec<PathBuf>),
    /// Changes were lost: every path may have been touched.
    Overflow,
}

/// A running watcher. Dropping it stops the thread.
pub struct Watch {
    handle: isize,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

const BUFFER_BYTES: usize = 64 * 1024;
const ERROR_NOTIFY_ENUM_DIR: i32 = 1022;

/// Starts watching `root` and everything below it; `on_signal` is called from the watcher's own
/// thread and returns `false` to stop it.
pub fn watch(
    root: &Path,
    on_signal: impl Fn(Signal) -> bool + Send + 'static,
) -> std::io::Result<Watch> {
    use std::os::windows::ffi::OsStrExt;
    let name: Vec<u16> = root.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: `name` is NUL-terminated.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let handle = handle as isize;
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let base = root.to_path_buf();
    let thread =
        std::thread::Builder::new().name("yadorilink-dir-watch".into()).spawn(move || {
            let mut buffer = vec![0u8; BUFFER_BYTES];
            while !stopping.load(Ordering::SeqCst) {
                let mut returned = 0u32;
                // SAFETY: `buffer` is writable for its length; the handle stays open until `Drop`
                // has cancelled this call and joined this thread.
                let ok = unsafe {
                    ReadDirectoryChangesW(
                        handle as HANDLE,
                        buffer.as_mut_ptr().cast::<c_void>(),
                        buffer.len() as u32,
                        1,
                        FILE_NOTIFY_CHANGE_FILE_NAME
                            | FILE_NOTIFY_CHANGE_DIR_NAME
                            | FILE_NOTIFY_CHANGE_SIZE
                            | FILE_NOTIFY_CHANGE_LAST_WRITE,
                        &mut returned,
                        std::ptr::null_mut(),
                        None,
                    )
                };
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                let signal = if ok == 0 {
                    match std::io::Error::last_os_error().raw_os_error() {
                        Some(ERROR_NOTIFY_ENUM_DIR) => Signal::Overflow,
                        // The directory went away or the handle was cancelled: nothing more to say.
                        _ => break,
                    }
                } else if returned == 0 {
                    Signal::Overflow
                } else {
                    Signal::Paths(parse(&buffer[..returned as usize], &base))
                };
                if !on_signal(signal) {
                    break;
                }
            }
        })?;
    Ok(Watch { handle, stop, thread: Some(thread) })
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // The worker may be just short of submitting its blocking read, where a cancel finds
        // nothing to cancel; cancelling again until it has ended covers that window.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let thread = self.thread.take();
        while thread.as_ref().is_some_and(|t| !t.is_finished())
            && std::time::Instant::now() < deadline
        {
            // SAFETY: `handle` is the open directory handle; cancelling wakes a blocked read.
            unsafe { CancelIoEx(self.handle as HANDLE, std::ptr::null()) };
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        match thread {
            Some(thread) if thread.is_finished() => {
                let _ = thread.join();
                // SAFETY: the thread that used the handle has ended.
                unsafe { CloseHandle(self.handle as HANDLE) };
            }
            // Still blocked after the deadline: the handle stays open with it rather than being
            // closed under a running read.
            _ => {}
        }
    }
}

/// The paths in one `FILE_NOTIFY_INFORMATION` chain: `NextEntryOffset`, `Action`,
/// `FileNameLength` (bytes), then the UTF-16 name relative to the watched directory.
fn parse(buffer: &[u8], base: &Path) -> Vec<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut paths = Vec::new();
    let mut offset = 0usize;
    while let Some(header) = buffer.get(offset..offset + 12) {
        let next = u32::from_le_bytes(header[0..4].try_into().expect("4 bytes")) as usize;
        let length = u32::from_le_bytes(header[8..12].try_into().expect("4 bytes")) as usize;
        let Some(name) = buffer.get(offset + 12..offset + 12 + length) else { break };
        let units: Vec<u16> = (0..name.len() / 2)
            .map(|i| u16::from_le_bytes([name[2 * i], name[2 * i + 1]]))
            .collect();
        paths.push(base.join(std::ffi::OsString::from_wide(&units)));
        if next == 0 {
            break;
        }
        offset += next;
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("yl-watch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn collect(rx: &std::sync::mpsc::Receiver<Signal>, want: &Path) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if let Ok(Signal::Paths(paths)) = rx.recv_timeout(Duration::from_millis(200)) {
                if paths.iter().any(|p| p == want) {
                    return true;
                }
            }
        }
        false
    }

    /// Create, modify, rename and delete anywhere below the root are all signalled with the
    /// paths involved (both names of a rename).
    #[test]
    fn changes_below_the_root_are_signalled_with_their_paths() {
        let dir = temp("signals");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let (tx, rx) = channel();
        let _watch = watch(&dir, move |signal| tx.send(signal).is_ok()).unwrap();

        let file = dir.join("sub").join("a.txt");
        std::fs::write(&file, b"one").unwrap();
        assert!(collect(&rx, &file), "create was not signalled");
        std::fs::write(&file, b"two").unwrap();
        assert!(collect(&rx, &file), "modify was not signalled");
        let renamed = dir.join("b.txt");
        std::fs::rename(&file, &renamed).unwrap();
        assert!(collect(&rx, &renamed), "the new name of a rename was not signalled");
        std::fs::remove_file(&renamed).unwrap();
        assert!(collect(&rx, &renamed), "delete was not signalled");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dropping_the_watcher_stops_it() {
        let dir = temp("drop");
        let (tx, rx) = channel();
        let watch = watch(&dir, move |signal| tx.send(signal).is_ok()).unwrap();
        drop(watch);
        std::fs::write(dir.join("late.txt"), b"x").unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_notification_chain_is_parsed_into_paths() {
        let entry = |name: &str, next: u32| {
            let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&next.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&(units.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&units);
            bytes
        };
        let mut first = entry("a.txt", 0);
        while first.len() % 4 != 0 {
            first.push(0);
        }
        let next = first.len() as u32;
        first[0..4].copy_from_slice(&next.to_le_bytes());
        first.extend(entry("sub\\日本語.txt", 0));
        let paths = parse(&first, Path::new(r"C:\root"));
        assert_eq!(
            paths,
            vec![PathBuf::from(r"C:\root\a.txt"), PathBuf::from(r"C:\root\sub\日本語.txt")]
        );
    }
}
