//! Windows Cloud Filter API (cfapi) integration for on-demand sync.
//! Runs inside the `yadorilink-cfapi-host` binary (see Cargo.toml's
//! `[[bin]]` doc comment for why this is a separate process from the
//! `yadorilink_shell_ext` COM DLL), not the shell extension DLL itself.
//!
//! Scope/known limitations, stated up front rather than discovered late:
//! - MVP hydrates whole files only (no byte-range
//!   hydration), so the sync root's `Hydration` policy is `FULL` and the
//!   fetch-data callback always serves the entire file regardless of the
//!   OS-requested range.
//! - Nested directories under an OnDemand folder are created as ordinary
//!   (non-placeholder) directories, not lazily-populated placeholder
//!   directories — `CfCreatePlaceholders` is only used for files. This
//!   matches the design's file-level (not directory-listing-level)
//!   on-demand scope.
//! - A placeholder's `FileIdentity` blob carries only the relative path
//!   as an opaque marker, not real block/version state: `CfCreatePlaceholders`
//!   documents `FileIdentity` as *mandatory for files* (confirmed the hard
//!   way — a null/empty identity fails with
//!   `ERROR_CLOUD_FILE_INVALID_REQUEST`, 0x8007017C, verified against real
//!   cfapi on a Windows 11 VM), so it can't be omitted; the daemon remains
//!   the sole source of truth for block/version state, looked up by path
//!   over shell-IPC in the fetch callback rather than decoded from this
//!   blob, avoiding a second, potentially-stale copy of that state.
//! - `hydration::hydrate` (the daemon-side function this ultimately
//!   drives, over shell-IPC's `HydrateRequest`) writes a placeholder's
//!   real content by reconstructing to a temp file and rename-replacing
//!   the target (`yadorilink_sync_core::chunker::reconstruct_file`) — this
//!   was written and tested against the platform-neutral placeholder
//!   representation on a non-Windows dev machine, not against
//!   a real cfapi reparse-point placeholder. A rename-replace over a file
//!   with an in-flight `CF_CALLBACK_TYPE_FETCH_DATA` callback is expected
//!   to work (the placeholder's reparse point and sparse ranges are
//!   simply replaced by an ordinary, fully-present file, which is a
//!   documented-valid way for a provider to "finish" a placeholder), but
//!   this specific interaction has NOT been exercised against a live
//!   Explorer file-open on real hardware.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use windows::core::{Result as WinResult, GUID, PCWSTR};
use windows::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
use windows::Win32::Storage::CloudFilters::{
    CfConnectSyncRoot, CfCreatePlaceholders, CfDisconnectSyncRoot, CfExecute, CfRegisterSyncRoot,
    CfUnregisterSyncRoot, CF_CALLBACK_INFO, CF_CALLBACK_PARAMETERS, CF_CALLBACK_REGISTRATION,
    CF_CALLBACK_TYPE_FETCH_DATA, CF_CALLBACK_TYPE_NONE, CF_CONNECT_FLAG_NONE, CF_CREATE_FLAG_NONE,
    CF_HARDLINK_POLICY_NONE, CF_HYDRATION_POLICY, CF_HYDRATION_POLICY_FULL,
    CF_HYDRATION_POLICY_MODIFIER_NONE, CF_INSYNC_POLICY_TRACK_ALL, CF_OPERATION_INFO,
    CF_OPERATION_PARAMETERS, CF_OPERATION_PARAMETERS_0, CF_OPERATION_PARAMETERS_0_6,
    CF_OPERATION_TRANSFER_DATA_FLAG_NONE, CF_OPERATION_TYPE_TRANSFER_DATA,
    CF_PLACEHOLDER_CREATE_FLAG_NONE, CF_PLACEHOLDER_CREATE_INFO,
    CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT, CF_POPULATION_POLICY,
    CF_POPULATION_POLICY_MODIFIER_NONE, CF_POPULATION_POLICY_PARTIAL, CF_REGISTER_FLAG_NONE,
    CF_SYNC_POLICIES, CF_SYNC_REGISTRATION,
};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_NORMAL, FILE_BASIC_INFO};
use yadorilink_ipc_proto::shellipc::MaterializationState;

/// Fixed provider identity. Namespace-derived, like the
/// overlay CLSIDs in `overlay.rs` — a real release would hand-pick and
/// never regenerate this, since `CfRegisterSyncRoot` ties a sync root's
/// registration to this GUID.
const PROVIDER_ID: GUID = GUID::from_u128(0x8f3a1c00_1e6b_4b7a_9d2e_1a2b3c4d5e20);
const PROVIDER_NAME: &str = "yadorilink";
const PROVIDER_VERSION: &str = "0.1.0";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// connection key (`CF_CONNECTION_KEY.0`) -> the local root path that
/// sync root was registered for, so the fetch-data callback (a bare
/// `extern "system" fn` with no way to receive a closure environment) can
/// resolve `CF_CALLBACK_INFO::NormalizedPath` (relative to the sync root)
/// back to an absolute path. Also indexed the other way (`KEYS_BY_ROOT`)
/// so `disconnect`/`unregister` can look up a root's connection key by
/// path — needed because `CfUnregisterSyncRoot` documents failing with
/// `ERROR_CLOUD_FILE_INVALID_REQUEST` if a provider is still connected
/// (confirmed the hard way against real cfapi), so unregistering this
/// process's own connection must disconnect it first.
static ROOTS_BY_CONNECTION: Mutex<Option<HashMap<i64, PathBuf>>> = Mutex::new(None);
static KEYS_BY_ROOT: Mutex<Option<HashMap<PathBuf, i64>>> = Mutex::new(None);

fn register_root(key: i64, local_path: &Path) {
    ROOTS_BY_CONNECTION
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(key, local_path.to_path_buf());
    KEYS_BY_ROOT
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(local_path.to_path_buf(), key);
}

fn root_for_connection(key: i64) -> Option<PathBuf> {
    ROOTS_BY_CONNECTION.lock().unwrap().as_ref()?.get(&key).cloned()
}

fn take_key_for_root(local_path: &Path) -> Option<i64> {
    let key = KEYS_BY_ROOT.lock().unwrap().as_mut()?.remove(local_path)?;
    ROOTS_BY_CONNECTION.lock().unwrap().as_mut().map(|m| m.remove(&key));
    Some(key)
}

/// Converts Unix nanoseconds since the epoch (`FileRecord::mtime_unix_nanos`)
/// to a Windows `FILETIME`-style tick count (100ns intervals since
/// 1601-01-01), as `FILE_BASIC_INFO`'s fields expect.
fn unix_nanos_to_filetime_ticks(unix_nanos: i64) -> i64 {
    const UNIX_EPOCH_IN_FILETIME_TICKS: i64 = 116_444_736_000_000_000;
    unix_nanos / 100 + UNIX_EPOCH_IN_FILETIME_TICKS
}

/// Registers `local_path` as a Cloud Filter API sync root and
/// connects it, wiring up the `CF_CALLBACK_TYPE_FETCH_DATA` handler.
/// Idempotent-ish: `CfRegisterSyncRoot` itself tolerates
/// re-registering the same root (it's meant to be called on every
/// provider startup, not just the first time — this is the documented
/// pattern, not a workaround).
///
/// Hydration policy is `FULL` (whole-file only — no partial/byte-range
/// hydration in this MVP) and population policy is `PARTIAL` (the
/// provider, not the OS, controls
/// which files are placeholders vs. fully present, which is exactly the
/// OnDemand model).
pub fn register_and_connect(local_path: &Path) -> WinResult<()> {
    let path_wide = wide(&local_path.to_string_lossy());
    let provider_name_wide = wide(PROVIDER_NAME);
    let provider_version_wide = wide(PROVIDER_VERSION);

    let registration = CF_SYNC_REGISTRATION {
        StructSize: std::mem::size_of::<CF_SYNC_REGISTRATION>() as u32,
        ProviderName: PCWSTR::from_raw(provider_name_wide.as_ptr()),
        ProviderVersion: PCWSTR::from_raw(provider_version_wide.as_ptr()),
        SyncRootIdentity: std::ptr::null(),
        SyncRootIdentityLength: 0,
        FileIdentity: std::ptr::null(),
        FileIdentityLength: 0,
        ProviderId: PROVIDER_ID,
    };

    let policies = CF_SYNC_POLICIES {
        StructSize: std::mem::size_of::<CF_SYNC_POLICIES>() as u32,
        Hydration: CF_HYDRATION_POLICY {
            Primary: CF_HYDRATION_POLICY_FULL,
            Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE,
        },
        Population: CF_POPULATION_POLICY {
            Primary: CF_POPULATION_POLICY_PARTIAL,
            Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
        },
        InSync: CF_INSYNC_POLICY_TRACK_ALL,
        HardLink: CF_HARDLINK_POLICY_NONE,
        PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
    };

    unsafe {
        CfRegisterSyncRoot(
            PCWSTR::from_raw(path_wide.as_ptr()),
            &registration,
            &policies,
            CF_REGISTER_FLAG_NONE,
        )?;
    }

    // Sentinel-terminated array: a `CF_CALLBACK_TYPE_NONE` entry marks the
    // end, per the documented `CfConnectSyncRoot` contract.
    let callbacks = [
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_FETCH_DATA,
            Callback: Some(fetch_data_callback),
        },
        CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NONE, Callback: None },
    ];

    let key = unsafe {
        CfConnectSyncRoot(
            PCWSTR::from_raw(path_wide.as_ptr()),
            callbacks.as_ptr(),
            None,
            CF_CONNECT_FLAG_NONE,
        )?
    };
    register_root(key.0, local_path);
    Ok(())
}

/// Disconnects this process's `CfConnectSyncRoot` connection for
/// `local_path`, if one was made via `register_and_connect` earlier in
/// this same process. A no-op (returns `Ok(())`) if this process never
/// connected to that root — connections are per-process, so there is
/// nothing for *this* process to disconnect in that case.
pub fn disconnect(local_path: &Path) -> WinResult<()> {
    let Some(key) = take_key_for_root(local_path) else { return Ok(()) };
    unsafe { CfDisconnectSyncRoot(windows::Win32::Storage::CloudFilters::CF_CONNECTION_KEY(key)) }
}

/// Unregisters a sync root, typically used during uninstallation.
///
/// `CfUnregisterSyncRoot` is documented to fail with
/// `ERROR_CLOUD_FILE_INVALID_REQUEST` if a sync provider is still
/// connected to the root (confirmed against real cfapi on a Windows 11
/// VM) — this disconnects first if *this process* holds a connection for
/// `local_path`. It does NOT reach into another process's connection:
/// the real long-lived `yadorilink-cfapi-host` process holds the actual
/// production connection, so callers driving the uninstall flow must
/// stop that process or its Scheduled Task before calling this,
/// not after — a connection is tied to process lifetime,
/// so stopping the process itself also tears down its connection.
pub fn unregister(local_path: &Path) -> WinResult<()> {
    let _ = disconnect(local_path);
    let path_wide = wide(&local_path.to_string_lossy());
    unsafe { CfUnregisterSyncRoot(PCWSTR::from_raw(path_wide.as_ptr())) }
}

/// Creates a cfapi placeholder for one file. `relative_path`
/// is forward-slash-separated (matching the shell-IPC wire format);
/// converted to backslashes here. The immediate parent directory is
/// created as an ordinary directory if missing (see module doc's
/// "nested directories" limitation).
pub fn create_placeholder(
    root: &Path,
    relative_path: &str,
    size: u64,
    mtime_unix_nanos: i64,
) -> WinResult<()> {
    let relative_path = relative_path.replace('/', "\\");
    let full_path = root.join(&relative_path);
    if let Some(parent) = full_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let base_dir = full_path.parent().unwrap_or(root);
    let file_name =
        full_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or(relative_path);

    let base_dir_wide = wide(&base_dir.to_string_lossy());
    let file_name_wide = wide(&file_name);
    let ticks = unix_nanos_to_filetime_ticks(mtime_unix_nanos);

    // `FileIdentity` is documented as a *mandatory* field for files (not
    // directories) in `CfCreatePlaceholders` — a null/empty identity was
    // originally tried (module doc's "prefer looking up hydration data by
    // path via IPC" simplification) but fails with
    // `ERROR_CLOUD_FILE_INVALID_REQUEST` (0x8007017C), confirmed against
    // real cfapi on a Windows 11 VM. The relative path's UTF-8 bytes are
    // used as a small, self-describing, well-under-4KB marker blob; the
    // fetch-data callback still resolves hydration data by looking up the
    // path via shell-IPC (not by decoding this blob) — this is not
    // duplicated block/version state, just enough of an opaque identity
    // to satisfy the API contract.
    let file_identity = file_name.as_bytes();

    let mut entries = [CF_PLACEHOLDER_CREATE_INFO {
        RelativeFileName: PCWSTR::from_raw(file_name_wide.as_ptr()),
        FsMetadata: windows::Win32::Storage::CloudFilters::CF_FS_METADATA {
            BasicInfo: FILE_BASIC_INFO {
                CreationTime: ticks,
                LastAccessTime: ticks,
                LastWriteTime: ticks,
                ChangeTime: ticks,
                FileAttributes: FILE_ATTRIBUTE_NORMAL.0,
            },
            FileSize: size as i64,
        },
        FileIdentity: file_identity.as_ptr() as *const c_void,
        FileIdentityLength: file_identity.len() as u32,
        Flags: CF_PLACEHOLDER_CREATE_FLAG_NONE,
        Result: windows::Win32::Foundation::S_OK,
        CreateUsn: 0,
    }];

    unsafe {
        CfCreatePlaceholders(
            PCWSTR::from_raw(base_dir_wide.as_ptr()),
            &mut entries,
            CF_CREATE_FLAG_NONE,
            None,
        )?;
    }
    entries[0].Result.ok()
}

/// The `CF_CALLBACK_TYPE_FETCH_DATA` handler, invoked by the
/// Cloud Filter driver, on an OS threadpool thread, whenever an
/// application's read reaches a dehydrated range of a placeholder under
/// one of this process's connected sync roots. Must always end by calling
/// `CfExecute(..., CF_OPERATION_TYPE_TRANSFER_DATA, ...)` — that call is
/// what unblocks the application's blocked `ReadFile`, whether hydration
/// succeeded or not (: a bounded failure, never a hang).
unsafe extern "system" fn fetch_data_callback(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    let info = &*callback_info;
    let params = &*callback_parameters;
    // Safety: `CF_CALLBACK_TYPE_FETCH_DATA` guarantees the `FetchData`
    // union arm is the active one, per the documented callback contract.
    let fetch = params.Anonymous.FetchData;

    let full_path = root_for_connection(info.ConnectionKey.0).map(|root| {
        let normalized = info.NormalizedPath.to_string().unwrap_or_default();
        let relative = normalized.trim_start_matches(['\\', '/']);
        root.join(relative)
    });

    let path_str = full_path.as_ref().and_then(|p| p.to_str().map(str::to_string));

    // Whole-file hydration only (module doc): request the daemon hydrate
    // the entire file, then serve the entire (now-real) file content back
    // to cfapi regardless of the specific offset/length the OS callback
    // asked for, since our sync policy only ever requests full files.
    let ok = path_str.as_deref().map(crate::ipc_client::hydrate).unwrap_or(false);

    let (buffer, status): (Vec<u8>, NTSTATUS) = if ok {
        match path_str.as_deref().map(std::fs::read) {
            Some(Ok(bytes)) => (bytes, STATUS_SUCCESS),
            _ => (Vec::new(), STATUS_UNSUCCESSFUL),
        }
    } else {
        (Vec::new(), STATUS_UNSUCCESSFUL)
    };

    let length = if status == STATUS_SUCCESS { buffer.len() as i64 } else { fetch.RequiredLength };

    let op_info = CF_OPERATION_INFO {
        StructSize: std::mem::size_of::<CF_OPERATION_INFO>() as u32,
        Type: CF_OPERATION_TYPE_TRANSFER_DATA,
        ConnectionKey: info.ConnectionKey,
        TransferKey: info.TransferKey,
        CorrelationVector: std::ptr::null(),
        SyncStatus: std::ptr::null(),
        RequestKey: info.RequestKey,
    };
    let mut op_params = CF_OPERATION_PARAMETERS {
        ParamSize: std::mem::size_of::<CF_OPERATION_PARAMETERS>() as u32,
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            TransferData: CF_OPERATION_PARAMETERS_0_6 {
                Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                CompletionStatus: status,
                Buffer: if buffer.is_empty() {
                    std::ptr::null()
                } else {
                    buffer.as_ptr() as *const c_void
                },
                Offset: 0,
                Length: length,
            },
        },
    };
    // Best-effort: if this itself fails there is nothing further this
    // callback can do to unblock the caller — the driver's own recall
    // timeout becomes the last resort. Not logged to stdout/stderr here
    // since a callback runs on an arbitrary threadpool thread inside a
    // long-lived host process; `yadorilink-cfapi-host`'s caller is expected
    // to run with console output visible for diagnosis if needed.
    let _ = CfExecute(&op_info, &mut op_params);
}

/// Convenience used by `yadorilink-cfapi-host`'s startup/poll loop: creates
/// placeholders for every file the daemon reports as
/// `MaterializationState::Placeholder` under `root` that don't already
/// have one on disk. Files already `Hydrated`/`Hydrating` are skipped —
/// they either already have real content or are actively being written
/// by a non-cfapi-routed hydration in progress, neither of which needs a
/// placeholder created.
pub fn sync_placeholders(root: &Path, entries: &[yadorilink_ipc_proto::shellipc::FolderFileEntry]) {
    for entry in entries {
        if MaterializationState::try_from(entry.materialization_state)
            != Ok(MaterializationState::Placeholder)
        {
            continue;
        }
        let full_path = root.join(entry.relative_path.replace('/', "\\"));
        if full_path.exists() {
            continue;
        }
        if let Err(e) =
            create_placeholder(root, &entry.relative_path, entry.size, entry.mtime_unix_nanos)
        {
            eprintln!(
                "yadorilink-cfapi-host: failed to create placeholder for {:?}: {e:?}",
                entry.relative_path
            );
        }
    }
}

#[cfg(test)]
mod tests {
    /// Manual diagnostic only (matches `registration.rs`'s
    /// `debug_register_all` pattern): exercises the real
    /// `CfRegisterSyncRoot`/`CfConnectSyncRoot`/`CfCreatePlaceholders`/
    /// `CfUnregisterSyncRoot` calls against a real directory on whatever
    /// machine runs it, independent of the daemon or CLI (no
    /// coordination-plane login needed) — the narrowest possible
    /// real-cfapi-runtime check. `#[ignore]`d since it
    /// touches real OS state; run explicitly with `cargo test --release
    /// -- --ignored cfapi_smoke_test` on a disposable Windows machine.
    #[test]
    #[ignore]
    fn cfapi_smoke_test() {
        let dir = std::env::temp_dir().join("yadorilink-cfapi-smoke-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");

        let reg = super::register_and_connect(&dir);
        println!("register_and_connect: {:?}", reg);
        reg.expect("CfRegisterSyncRoot/CfConnectSyncRoot should succeed");

        let now_nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                as i64;
        let create = super::create_placeholder(&dir, "hello.txt", 11, now_nanos);
        println!("create_placeholder: {:?}", create);
        create.expect("CfCreatePlaceholders should succeed");

        let placeholder_path = dir.join("hello.txt");
        let attrs = unsafe {
            windows::Win32::Storage::FileSystem::GetFileAttributesW(
                windows::core::PCWSTR::from_raw(
                    super::wide(&placeholder_path.to_string_lossy()).as_ptr(),
                ),
            )
        };
        println!("placeholder file attributes: {attrs:#x}");
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        assert!(
            attrs != u32::MAX && attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0,
            "expected the created placeholder to have FILE_ATTRIBUTE_REPARSE_POINT set, got {attrs:#x}"
        );

        let unreg = super::unregister(&dir);
        println!("unregister: {:?}", unreg);
        unreg.expect("CfUnregisterSyncRoot should succeed");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
