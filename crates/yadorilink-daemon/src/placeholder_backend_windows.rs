//! Windows Cloud Filter API (`CfApi`) `PlaceholderBackend`: a real
//! OS-transparent placeholder, replacing the ordinary sparse file
//! `yadorilink_local_storage::write_placeholder` writes (see that
//! function's own doc comment for exactly what this closes).
//!
//! A sync root must be registered (`CfRegisterSyncRoot`) before any
//! placeholder can be created inside it; `WindowsCfApiBackend::register`
//! does that once per link root, mirroring
//! `yadorilink_root_authority::sync_root_lock::SyncRootLock`'s "acquired once,
//! held for the link's lifetime" shape. Dropping the backend unregisters
//! the root.
//!
//! # What this does NOT implement
//!
//! The OS-triggered fetch callback (`CfConnectSyncRoot` plus a
//! `CF_CALLBACK_REGISTRATION` table for `FETCH_DATA`/`CANCEL_FETCH_DATA`/
//! `VALIDATE_DATA`/`FETCH_PLACEHOLDERS`) is NOT wired up. That callback is
//! what makes double-clicking a placeholder in Explorer transparently
//! trigger a real-time block fetch without any explicit daemon-initiated
//! action — the piece that makes on-demand sync feel exactly like a normal
//! folder to the end user. Building it requires a persistent
//! `CfConnectSyncRoot` connection with a live callback-dispatch thread
//! translating OS fetch requests into calls into this crate's own sync
//! engine (fetching blocks from a peer, then `CfExecute`/
//! `CfReportProviderProgress` to stream the answer back) — a second,
//! comparably-sized project on top of this one, deliberately left for a
//! follow-up pass. What IS implemented and real: sync-root registration,
//! placeholder creation with an opaque generation token stored as this
//! placeholder's file identity, dirty detection via the OS's own
//! `CF_PLACEHOLDER_STATE_IN_SYNC` bit (not size/mtime), and daemon-driven
//! hydration (marking a placeholder in-sync once this process has already
//! written real content to it) — everything the `PlaceholderBackend` trait
//! itself requires.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE};
use windows_sys::Win32::Storage::CloudFilters::{
    CfConnectSyncRoot, CfCreatePlaceholders, CfDisconnectSyncRoot, CfExecute, CfGetPlaceholderInfo,
    CfGetPlaceholderStateFromFileInfo, CfGetTransferKey, CfRegisterSyncRoot, CfUnregisterSyncRoot,
    CfUpdatePlaceholder, CF_CALLBACK_REGISTRATION, CF_CALLBACK_TYPE_NONE, CF_CONNECTION_KEY,
    CF_CONNECT_FLAG_NONE, CF_CREATE_FLAG_NONE, CF_FS_METADATA, CF_OPERATION_INFO,
    CF_OPERATION_PARAMETERS, CF_OPERATION_PARAMETERS_0, CF_OPERATION_PARAMETERS_0_6,
    CF_OPERATION_TRANSFER_DATA_FLAG_NONE, CF_OPERATION_TYPE_TRANSFER_DATA,
    CF_PLACEHOLDER_BASIC_INFO, CF_PLACEHOLDER_CREATE_FLAG_ALWAYS_FULL,
    CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC, CF_PLACEHOLDER_CREATE_INFO, CF_PLACEHOLDER_INFO_BASIC,
    CF_PLACEHOLDER_STATE_INVALID, CF_PLACEHOLDER_STATE_IN_SYNC, CF_PLACEHOLDER_STATE_PLACEHOLDER,
    CF_REGISTER_FLAG_UPDATE, CF_SYNC_POLICIES, CF_SYNC_REGISTRATION, CF_UPDATE_FLAG_MARK_IN_SYNC,
    CF_UPDATE_FLAG_VERIFY_IN_SYNC,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandleEx, GetFileSizeEx, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};

use yadorilink_filesystem_sync::placeholder_backend::{
    PlaceholderBackend, PlaceholderCapability, PlaceholderGeneration, PlaceholderStatus,
};
use yadorilink_root_authority::RootAuthorityError;

const PROVIDER_NAME: &str = "yadorilink-cfapi";
const PROVIDER_VERSION: &str = "1";

fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

fn hresult_err(context: &str, hr: i32) -> RootAuthorityError {
    RootAuthorityError::Io(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("{context}: HRESULT 0x{hr:08X}"),
    ))
}

/// Like `hresult_err`, but for an error surfaced via `GetLastError()`
/// (`CreateFileW`/`GetFileSizeEx` and friends -- APIs that signal failure
/// through the calling thread's last-error code, not an `HRESULT` return
/// value). Converts through the standard `HRESULT_FROM_WIN32` formula
/// rather than passing the raw Win32 code where an HRESULT is expected --
/// passing it unconverted produced misleading messages like "HRESULT
/// 0x00000005" (which reads as `S_OK`'s facility with a made-up severity
/// bit unset) instead of the correct `0x80070005`.
fn win32_err(context: &str, win32_code: u32) -> RootAuthorityError {
    const FACILITY_WIN32: u32 = 0x0007;
    let hr = (win32_code & 0x0000_FFFF) | (FACILITY_WIN32 << 16) | 0x8000_0000;
    hresult_err(context, hr as i32)
}

/// A sync root registered with the Cloud Filter API. Registration happens
/// once (`register`), for as long as this link is watched — mirroring
/// `SyncRootLock`'s exact lifecycle. Every `PlaceholderBackend` call takes
/// `&self`, so a caller must keep this alive for the link's whole life, not
/// construct-and-drop it per call.
pub struct WindowsCfApiBackend {
    root: std::path::PathBuf,
    /// A live `CfConnectSyncRoot` connection, held for as long as this
    /// backend exists. Required, not optional: the Cloud Filter filter
    /// driver refuses ordinary file operations (even a read-only
    /// attribute query) against a placeholder under a sync root with no
    /// connected provider -- confirmed empirically (`CreateFileW` on a
    /// just-created placeholder failed until this connection was added).
    /// The callback table below registers no real callbacks (`CF_CALLBACK_
    /// TYPE_NONE` terminator only) -- see this module's own doc for why
    /// the OS-triggered fetch callback itself is out of scope for this
    /// pass; this connection exists solely to make the driver consider the
    /// root "online" for the synchronous calls this backend actually uses.
    connection_key: CF_CONNECTION_KEY,
}

impl WindowsCfApiBackend {
    /// Registers `root` as a Cloud Filter sync root. Idempotent: the API
    /// itself treats re-registering the same path as an update, not an
    /// error, so a restarted daemon picking the same link back up does not
    /// need to unregister first.
    pub fn register(root: &Path) -> Result<Self, RootAuthorityError> {
        let root = root.canonicalize().map_err(|e| {
            RootAuthorityError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to resolve sync root {}: {e}", root.display()),
            ))
        })?;
        let wide_root = to_wide(&root);
        let provider_name: Vec<u16> =
            PROVIDER_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let provider_version: Vec<u16> =
            PROVIDER_VERSION.encode_utf16().chain(std::iter::once(0)).collect();
        let registration = CF_SYNC_REGISTRATION {
            StructSize: std::mem::size_of::<CF_SYNC_REGISTRATION>() as u32,
            ProviderName: provider_name.as_ptr(),
            ProviderVersion: provider_version.as_ptr(),
            // Not asserted: no `CfConnectSyncRoot` callback loop exists to
            // answer with (see this module's own doc). A blob distinguishing
            // this yadorilink installation is out of scope until that
            // callback loop is built.
            SyncRootIdentity: std::ptr::null(),
            SyncRootIdentityLength: 0,
            FileIdentity: std::ptr::null(),
            FileIdentityLength: 0,
            ProviderId: windows_sys::core::GUID::from_u128(0),
        };
        // Left zero-initialized (`CF_HYDRATION_POLICY_PARTIAL`/
        // `CF_POPULATION_POLICY_PARTIAL`) deliberately, despite Microsoft
        // documenting `PARTIAL` hydration as unsupported: setting BOTH
        // Hydration and Population to `ALWAYS_FULL` together (matching the
        // per-placeholder `CF_PLACEHOLDER_CREATE_FLAG_ALWAYS_FULL` already
        // used in `create`) was tried and measured to break
        // `CfCreatePlaceholders` outright on this real Windows 11 (build
        // 26200) machine (`HRESULT 0x8007017C`, "The cloud operation is
        // invalid"). Root-level Hydration `ALWAYS_FULL` alone is
        // documented to reject `CfCreatePlaceholders` (a placeholder is,
        // by definition, not-yet-fully-hydrated content, which an
        // always-fully-hydrated root cannot represent) -- this change
        // varied both policies at once, so it does NOT establish that
        // Population `ALWAYS_FULL` specifically was the (or a) cause, only
        // that the combination together breaks placeholder creation.
        // Reverted to the zeroed defaults, which this module's own smoke
        // test (`tests/windows_cfapi_smoke.rs`) confirms actually works end
        // to end. Finding a real, measured-correct non-default policy
        // combination (if `Population` alone can safely be `ALWAYS_FULL`
        // while `Hydration` stays `PARTIAL`, for instance) is follow-up
        // work, not a hygiene fix to make blind.
        let policies = CF_SYNC_POLICIES {
            StructSize: std::mem::size_of::<CF_SYNC_POLICIES>() as u32,
            ..unsafe { std::mem::zeroed() }
        };
        // SAFETY: `wide_root`/`provider_name`/`provider_version` are valid,
        // NUL-terminated UTF-16 buffers kept alive for the whole call;
        // `registration`/`policies` are valid, correctly-sized structs.
        // `CF_REGISTER_FLAG_UPDATE`, not `_NONE`: registration is
        // persistent across process restarts, and this call must actually
        // be idempotent (a restarted daemon picking the same link back up
        // re-registers the same root) -- `_NONE` only succeeds for a
        // never-before-registered path.
        let hr = unsafe {
            CfRegisterSyncRoot(
                wide_root.as_ptr(),
                &registration,
                &policies,
                CF_REGISTER_FLAG_UPDATE,
            )
        };
        if hr < 0 {
            return Err(hresult_err(
                &format!("CfRegisterSyncRoot failed for {}", root.display()),
                hr,
            ));
        }
        // Terminator-only callback table: no real callback is registered
        // (see this struct's own `connection_key` doc for why this
        // connection exists at all without one).
        let callback_table =
            [CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NONE, Callback: None }];
        let mut connection_key: CF_CONNECTION_KEY = 0;
        // SAFETY: `wide_root` is a valid NUL-terminated UTF-16 buffer;
        // `callback_table` is a valid, `CF_CALLBACK_TYPE_NONE`-terminated
        // array; `connection_key` is a valid out-pointer.
        let hr = unsafe {
            CfConnectSyncRoot(
                wide_root.as_ptr(),
                callback_table.as_ptr(),
                std::ptr::null(),
                CF_CONNECT_FLAG_NONE,
                &mut connection_key,
            )
        };
        if hr < 0 {
            // SAFETY: `wide_root` is the same valid buffer used above.
            unsafe {
                CfUnregisterSyncRoot(wide_root.as_ptr());
            }
            return Err(hresult_err(
                &format!("CfConnectSyncRoot failed for {}", root.display()),
                hr,
            ));
        }
        Ok(Self { root, connection_key })
    }

    fn open_reparse_handle(path: &Path, write: bool) -> Result<HANDLE, RootAuthorityError> {
        let wide = to_wide(path);
        let access = if write { GENERIC_WRITE } else { 0 };
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 buffer for the
        // duration of this call.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle.is_null() || handle as isize == -1 {
            // `CreateFileW` reports failure via `GetLastError`, not an
            // HRESULT return.
            return Err(win32_err(
                &format!("CreateFileW failed opening {} for placeholder access", path.display()),
                unsafe { windows_sys::Win32::Foundation::GetLastError() },
            ));
        }
        Ok(handle)
    }

    /// Reads back the `FileIdentity` bytes this placeholder was created
    /// (or last updated) with, via `CfGetPlaceholderInfo(CF_PLACEHOLDER_
    /// INFO_BASIC)`. `None` on any failure -- a caller that cannot read
    /// the identity back must not assume it matches.
    fn read_placeholder_identity(handle: HANDLE) -> Option<Vec<u8>> {
        // `CF_PLACEHOLDER_BASIC_INFO::FileIdentity` is a C flexible-array
        // member (`[u8; 1]` in the binding): the real identity bytes
        // follow the fixed-size header in the same buffer, so the buffer
        // passed to `CfGetPlaceholderInfo` must be sized generously beyond
        // `size_of::<CF_PLACEHOLDER_BASIC_INFO>()` -- this backend's own
        // identity is a fixed 8 bytes (`PlaceholderGeneration`'s `u64`),
        // so 64 bytes of headroom is far more than ever needed.
        const IDENTITY_HEADROOM: usize = 64;
        let mut buf =
            vec![0u8; std::mem::size_of::<CF_PLACEHOLDER_BASIC_INFO>() + IDENTITY_HEADROOM];
        let mut returned: u32 = 0;
        // SAFETY: `handle` is a valid, open handle; `buf` is sized to hold
        // at least a full `CF_PLACEHOLDER_BASIC_INFO` plus headroom for
        // the trailing identity bytes.
        let hr = unsafe {
            CfGetPlaceholderInfo(
                handle,
                CF_PLACEHOLDER_INFO_BASIC,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut returned,
            )
        };
        if hr < 0 {
            return None;
        }
        // SAFETY: `buf` was just populated by the call above, which
        // reported success, so at least `size_of::<CF_PLACEHOLDER_BASIC_
        // INFO>()` bytes are valid; `read_unaligned` does not require the
        // buffer to be aligned for the struct type.
        let info: CF_PLACEHOLDER_BASIC_INFO =
            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const CF_PLACEHOLDER_BASIC_INFO) };
        let identity_offset = std::mem::offset_of!(CF_PLACEHOLDER_BASIC_INFO, FileIdentity);
        let len = info.FileIdentityLength as usize;
        if identity_offset.checked_add(len)? > buf.len() {
            return None;
        }
        Some(buf[identity_offset..identity_offset + len].to_vec())
    }
}

impl Drop for WindowsCfApiBackend {
    fn drop(&mut self) {
        // SAFETY: `self.connection_key` was returned by this same struct's
        // `CfConnectSyncRoot` call in `register`. Best-effort, like the
        // unregister below: nothing left to do with a failure at drop time.
        let _ = unsafe { CfDisconnectSyncRoot(self.connection_key) };
        let wide_root = to_wide(&self.root);
        // SAFETY: `wide_root` is a valid NUL-terminated UTF-16 buffer.
        // Best-effort: nothing left to do with a failure here at drop time,
        // and an already-unregistered root (e.g. a concurrent unlink)
        // reporting an error is expected, not a bug to propagate.
        let _ = unsafe { CfUnregisterSyncRoot(wide_root.as_ptr()) };
    }
}

impl PlaceholderBackend for WindowsCfApiBackend {
    fn probe(_root: &Path) -> PlaceholderCapability {
        // `CfRegisterSyncRoot` and friends are part of `cldapi.dll`,
        // present on Windows 10 1709+ and every supported Windows 11
        // release; this crate's minimum supported Windows version already
        // meets that floor (see `windows_pipe_security`'s own platform
        // assumptions), so no separate version probe is needed beyond
        // "this is Windows" (this module is `#[cfg(windows)]` already).
        PlaceholderCapability::Supported { name: "windows-cfapi" }
    }

    fn create(
        &self,
        path: &std::path::Path,
        size: u64,
        mtime_unix_nanos: i64,
    ) -> Result<PlaceholderGeneration, RootAuthorityError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let generation = PlaceholderGeneration(
            // A real generation source, not a constant: two placeholders
            // created back-to-back for the same path (e.g. a delete
            // immediately followed by a re-create) must not mint the same
            // token, or `inspect` could not tell them apart.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1),
        );
        let file_name = path.file_name().ok_or_else(|| {
            RootAuthorityError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("placeholder path {} has no file name", path.display()),
            ))
        })?;
        let wide_name = to_wide(std::path::Path::new(file_name));
        let identity = generation.0.to_le_bytes();
        let mtime_filetime = unix_nanos_to_filetime(mtime_unix_nanos);
        let mut create_info = CF_PLACEHOLDER_CREATE_INFO {
            RelativeFileName: wide_name.as_ptr(),
            FsMetadata: CF_FS_METADATA {
                BasicInfo: windows_sys::Win32::Storage::FileSystem::FILE_BASIC_INFO {
                    CreationTime: mtime_filetime,
                    LastAccessTime: mtime_filetime,
                    LastWriteTime: mtime_filetime,
                    ChangeTime: mtime_filetime,
                    FileAttributes: FILE_ATTRIBUTE_NORMAL,
                },
                FileSize: size as i64,
            },
            FileIdentity: identity.as_ptr() as *const c_void,
            FileIdentityLength: identity.len() as u32,
            // MARK_IN_SYNC: this backend always knows the correct
            // size/mtime at creation time (unlike a lazily-populating
            // provider), so there is nothing "pending" about a freshly
            // created placeholder -- confirmed empirically that omitting
            // this creates it in a NOT-in-sync state (`CF_PLACEHOLDER_
            // STATE_PARTIAL | PARTIALLY_ON_DISK`, no `IN_SYNC` bit), which
            // would make `inspect` report a brand-new placeholder as
            // already `Dirty`.
            //
            // ALWAYS_FULL: without it, an ordinary local write into this
            // placeholder's unpopulated byte range makes the OS attempt to
            // fetch that range first -- confirmed empirically (a plain
            // `std::fs::write` after `create` timed out with "The cloud
            // operation was not completed before the time-out period
            // expired") -- because no `FETCH_DATA` callback is registered
            // (see this module's own top-level doc for why that callback
            // is out of scope this pass). This flag tells the OS this
            // placeholder's data needs no such fetch, so `hydrate`'s
            // contract ("the caller already wrote real content with
            // ordinary filesystem calls, before calling `hydrate`") is
            // actually deliverable without that callback. The real,
            // load-bearing part of THIS pass -- OS-tracked, non-size/mtime
            // dirty detection via `CF_PLACEHOLDER_STATE_IN_SYNC` -- does
            // not depend on genuine lazy fetch-on-open working; only the
            // "OS itself streams remote content transparently on open"
            // user experience does, and that piece is the explicitly
            // deferred one.
            Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC | CF_PLACEHOLDER_CREATE_FLAG_ALWAYS_FULL,
            Result: 0,
            CreateUsn: 0,
        };
        let parent = path.parent().unwrap_or(&self.root);
        let wide_parent = to_wide(parent);
        let mut processed: u32 = 0;
        // SAFETY: `wide_parent` and `wide_name` are valid NUL-terminated
        // UTF-16 buffers; `create_info` is a single, correctly-sized,
        // valid entry; `identity` outlives this call.
        let hr = unsafe {
            CfCreatePlaceholders(
                wide_parent.as_ptr(),
                &mut create_info,
                1,
                CF_CREATE_FLAG_NONE,
                &mut processed,
            )
        };
        if hr < 0 || create_info.Result < 0 {
            return Err(hresult_err(
                &format!("CfCreatePlaceholders failed for {}", path.display()),
                if hr < 0 { hr } else { create_info.Result },
            ));
        }
        Ok(generation)
    }

    fn inspect(
        &self,
        path: &std::path::Path,
        expected: PlaceholderGeneration,
    ) -> Result<PlaceholderStatus, RootAuthorityError> {
        let handle = match Self::open_reparse_handle(path, false) {
            Ok(h) => h,
            // Gone, or genuinely inaccessible: cannot tell "still the
            // placeholder we created" from "replaced" -- fail closed.
            Err(_) => return Ok(PlaceholderStatus::Unknown),
        };
        let close = || unsafe {
            CloseHandle(handle);
        };
        let mut attr_tag: windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_TAG_INFO =
            unsafe { std::mem::zeroed() };
        // SAFETY: `handle` is a valid, open handle to `path`; `attr_tag` is
        // correctly sized for `FileAttributeTagInfo`.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                windows_sys::Win32::Storage::FileSystem::FileAttributeTagInfo,
                &mut attr_tag as *mut _ as *mut c_void,
                std::mem::size_of_val(&attr_tag) as u32,
            )
        };
        if ok == 0 {
            close();
            return Ok(PlaceholderStatus::Unknown);
        }
        // SAFETY: `attr_tag` was just populated by the call above.
        let state = unsafe {
            CfGetPlaceholderStateFromFileInfo(
                &attr_tag as *const _ as *const c_void,
                windows_sys::Win32::Storage::FileSystem::FileAttributeTagInfo,
            )
        };
        if state == CF_PLACEHOLDER_STATE_INVALID || state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0 {
            // No longer a placeholder at all (hydrated in place by
            // something other than this backend's own `hydrate`, or
            // replaced outright). Cannot confirm it is still ours.
            close();
            return Ok(PlaceholderStatus::Unknown);
        }
        // Read back the generation token this placeholder actually carries
        // and compare against `expected` -- this is the ABA guard the
        // trait's own doc promises ("minted at creation and compared, not
        // recomputed, at inspect time"): without it, a placeholder deleted
        // and replaced by an unrelated, genuinely in-sync placeholder at
        // the same path would report `Untouched` for a caller still
        // holding the OLD generation, silently treating a different
        // object as the one it created.
        let identity = Self::read_placeholder_identity(handle);
        close();
        let expected_bytes = expected.0.to_le_bytes();
        match identity {
            Some(bytes) if bytes == expected_bytes => {}
            _ => return Ok(PlaceholderStatus::Unknown),
        }
        if state & CF_PLACEHOLDER_STATE_IN_SYNC != 0 {
            Ok(PlaceholderStatus::Untouched)
        } else {
            Ok(PlaceholderStatus::Dirty)
        }
    }

    fn hydrate(
        &self,
        path: &std::path::Path,
        content: &mut dyn std::io::Read,
    ) -> Result<(), RootAuthorityError> {
        let handle = Self::open_reparse_handle(path, true)?;
        let outcome = self.hydrate_inner(handle, path, content);
        unsafe {
            CloseHandle(handle);
        }
        outcome
    }
}

impl WindowsCfApiBackend {
    /// The fallible body of `hydrate`, split out so the handle above is
    /// closed exactly once regardless of which step below fails.
    ///
    /// `CfUpdatePlaceholder(MARK_IN_SYNC)` is reached ONLY when
    /// `transfer_content` fully succeeded AND the placeholder's logical
    /// size (queried fresh via `GetFileSizeEx`, not assumed) matches the
    /// byte count actually transferred -- a placeholder left partially or
    /// never populated must never be marked in-sync, or `inspect` would
    /// report `Untouched` for content that was never really written.
    fn hydrate_inner(
        &self,
        handle: HANDLE,
        path: &std::path::Path,
        content: &mut dyn std::io::Read,
    ) -> Result<(), RootAuthorityError> {
        let transferred = self.transfer_content(handle, path, content)?;
        let mut logical_size: i64 = 0;
        // SAFETY: `handle` is a valid, open handle to `path`.
        let ok = unsafe { GetFileSizeEx(handle, &mut logical_size) };
        if ok == 0 {
            return Err(win32_err(
                &format!("GetFileSizeEx failed for {} after hydrate transfer", path.display()),
                unsafe { windows_sys::Win32::Foundation::GetLastError() },
            ));
        }
        if logical_size < 0 || transferred != logical_size as u64 {
            return Err(RootAuthorityError::Io(std::io::Error::other(format!(
                "hydrate for {} transferred {transferred} bytes but the placeholder's logical \
                 size is {logical_size}; refusing to mark it in-sync with a size mismatch",
                path.display()
            ))));
        }
        let mut usn: i64 = 0;
        // SAFETY: `handle` is a valid, open, writable handle to `path`;
        // every pointer argument the API allows to be null is null here
        // (no metadata update, no identity change, no dehydration range).
        let hr = unsafe {
            CfUpdatePlaceholder(
                handle,
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                // `VERIFY_IN_SYNC`, not `MARK_IN_SYNC` alone: `handle` was
                // opened with `FILE_SHARE_WRITE` (`open_reparse_handle`),
                // so a local writer can modify or resize the file between
                // `transfer_content`'s last `CfExecute` call and this one
                // -- `MARK_IN_SYNC` alone would silently bless that
                // concurrent local write as "in sync", after which
                // `inspect` would report `Untouched` for content this
                // backend never actually wrote. `VERIFY_IN_SYNC` makes the
                // OS itself refuse to mark in-sync if the file changed
                // since the placeholder's last known-good state.
                CF_UPDATE_FLAG_VERIFY_IN_SYNC | CF_UPDATE_FLAG_MARK_IN_SYNC,
                &mut usn,
                std::ptr::null_mut(),
            )
        };
        if hr < 0 {
            return Err(hresult_err(
                &format!("CfUpdatePlaceholder failed marking {} in-sync", path.display()),
                hr,
            ));
        }
        Ok(())
    }
}

impl WindowsCfApiBackend {
    /// Streams `content` into the placeholder behind `handle` via
    /// `CfExecute(CF_OPERATION_TYPE_TRANSFER_DATA)` -- the provider-side
    /// data-population path an ordinary `WriteFile`/`std::fs::write` cannot
    /// substitute for (see `hydrate`'s own trait doc for why). Chunked so a
    /// large file is never held in memory whole.
    fn transfer_content(
        &self,
        handle: HANDLE,
        path: &std::path::Path,
        content: &mut dyn std::io::Read,
    ) -> Result<u64, RootAuthorityError> {
        // SAFETY: `handle` is a valid, open handle to the placeholder this
        // call is populating.
        let mut transfer_key: i64 = 0;
        let hr = unsafe { CfGetTransferKey(handle, &mut transfer_key) };
        if hr < 0 {
            return Err(hresult_err(
                &format!("CfGetTransferKey failed for {}", path.display()),
                hr,
            ));
        }
        let mut offset: i64 = 0;
        // 1 MiB, a multiple of 4 KiB: CfExecute(TRANSFER_DATA) requires
        // every transfer's offset AND length to be 4 KiB-aligned, except
        // for a final range ending at or beyond the placeholder's logical
        // EOF (Microsoft's CF_OPERATION_PARAMETERS docs) -- `Read::read`
        // is explicitly permitted to return short of a full buffer for
        // reasons that have nothing to do with EOF (a slow/chunked
        // reader), so forwarding whatever one `read` call happened to
        // return, as an earlier version of this function did, could
        // dispatch a short, non-final, misaligned transfer and have
        // CfExecute legitimately reject it even though `content` would
        // have gone on to deliver the exact declared size. The inner loop
        // below instead fills `buf` completely (or hits genuine EOF)
        // before every dispatch, so only the LAST dispatch -- the one
        // where `filled < buf.len()`, which `hydrate_inner`'s own size
        // check confirms lands exactly at logical EOF -- is ever short.
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let mut filled = 0usize;
            while filled < buf.len() {
                match content.read(&mut buf[filled..]).map_err(RootAuthorityError::Io)? {
                    0 => break,
                    n => filled += n,
                }
            }
            if filled == 0 {
                break;
            }
            let n = filled;
            let op_info = CF_OPERATION_INFO {
                StructSize: std::mem::size_of::<CF_OPERATION_INFO>() as u32,
                Type: CF_OPERATION_TYPE_TRANSFER_DATA,
                ConnectionKey: self.connection_key,
                TransferKey: transfer_key,
                CorrelationVector: std::ptr::null(),
                SyncStatus: std::ptr::null(),
                RequestKey: 0,
            };
            let mut op_params = CF_OPERATION_PARAMETERS {
                ParamSize: std::mem::size_of::<CF_OPERATION_PARAMETERS>() as u32,
                Anonymous: CF_OPERATION_PARAMETERS_0 {
                    TransferData: CF_OPERATION_PARAMETERS_0_6 {
                        Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                        // STATUS_SUCCESS -- this provider always has the
                        // bytes it is transferring (they came from its own
                        // already-assembled `content` reader, never a
                        // partial/failed fetch), so every chunk reports
                        // success.
                        CompletionStatus: 0,
                        Buffer: buf.as_ptr() as *const c_void,
                        Offset: offset,
                        Length: n as i64,
                    },
                },
            };
            // SAFETY: `op_info` and `op_params` are valid, correctly-sized,
            // fully-initialized structs; `buf[..n]` outlives this call.
            let hr = unsafe { CfExecute(&op_info, &mut op_params) };
            if hr < 0 {
                return Err(hresult_err(
                    &format!(
                        "CfExecute(TRANSFER_DATA) failed for {} at offset {offset}",
                        path.display()
                    ),
                    hr,
                ));
            }
            offset += n as i64;
        }
        Ok(offset as u64)
    }
}

fn unix_nanos_to_filetime(unix_nanos: i64) -> i64 {
    // FILETIME: 100ns intervals since 1601-01-01. Unix epoch offset in
    // 100ns units, the standard constant for this conversion.
    const UNIX_EPOCH_IN_FILETIME_100NS: i64 = 116_444_736_000_000_000;
    if unix_nanos < 0 {
        return UNIX_EPOCH_IN_FILETIME_100NS;
    }
    UNIX_EPOCH_IN_FILETIME_100NS + unix_nanos / 100
}

// Tested via `tests/windows_cfapi_smoke.rs` (an integration test, not a
// `--lib` unit test): that only needs this crate's compiled rlib, not the
// whole crate's `#[cfg(test)]` module graph, part of which is not yet
// Windows-portable (unrelated to this module).

/// This crate's half of [`select_placeholder_backend`] -- the only
/// constructor for a real [`PlaceholderBackend`] on Windows. Registration
/// failure (no `SeCreateSymbolicLinkPrivilege`-style precondition on this
/// path, but `CfRegisterSyncRoot` can still fail, e.g. `root` already
/// registered by another provider) returns `None`, matching this function's
/// contract of "no provider available" rather than propagating a Windows
/// error type into a cross-platform caller.
pub(crate) fn select_placeholder_backend(root: &Path) -> Option<Arc<dyn PlaceholderBackend>> {
    match WindowsCfApiBackend::register(root) {
        Ok(backend) => Some(Arc::new(backend)),
        Err(e) => {
            tracing::warn!(
                root = %root.display(),
                error = %e,
                "failed to register Windows Cloud Filter API sync root for placeholder provider"
            );
            None
        }
    }
}
