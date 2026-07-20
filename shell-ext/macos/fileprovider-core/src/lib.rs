//! The "thin Rust core" behind
//! `NSFileProviderReplicatedExtension` (`YadoriLinkFileProvider`), the File
//! Provider extension-point counterpart of `shell-ext/macos/core` (which
//! backs the FinderSync extension point — see this crate's Cargo.toml
//! for why they're separate crates rather than one shared staticlib).
//!
//! Same fail-soft/bounded-timeout/`catch_unwind` contract as `core::lib`:
//! every exported function must never block its caller past the timeout
//! documented in `ipc_client`, and must never let a panic unwind across
//! the FFI boundary (undefined behavior in a staticlib).
//!
//! Lists (folder discovery, per-folder file enumeration) cross the FFI
//! boundary as a single heap-allocated, NUL-terminated JSON C string
//! rather than a C array-of-structs — see Cargo.toml's doc comment for
//! why. Every function that returns `*mut c_char` transfers ownership of
//! that allocation to the caller, who must free it with
//! `yadorilink_fp_free_string` exactly once (never with `free(3)` directly —
//! the allocation was made by Rust's global allocator via `CString`,
//! which is not guaranteed to be `libc`'s `malloc` on every target).

mod ipc_client;

use std::ffi::{c_char, CStr, CString};
use std::panic::catch_unwind;

/// # Safety
/// `path` must be a valid, null-terminated C string for the duration of
/// this call, or NULL (in which case `None` is returned rather than
/// dereferencing).
unsafe fn path_from_c_str(path: *const c_char) -> Option<String> {
    if path.is_null() {
        return None;
    }
    CStr::from_ptr(path).to_str().ok().map(str::to_owned)
}

/// Converts a `Serialize`-able value to an owned, heap-allocated C string
/// the caller must later pass to `yadorilink_fp_free_string`. Serialization
/// failure (should not happen for these plain-data types, but must never
/// panic across FFI) falls back to `"[]"`/`"{}"`-shaped empty JSON so the
/// Swift side's `JSONDecoder` never sees malformed input.
fn to_c_json<T: serde::Serialize>(value: &T, empty_fallback: &str) -> *mut c_char {
    let json = serde_json::to_string(value).unwrap_or_else(|_| empty_fallback.to_string());
    CString::new(json).unwrap_or_else(|_| CString::new(empty_fallback).unwrap()).into_raw()
}

/// Frees a C string previously returned by any `yadorilink_fp_*` function
/// that returns `*mut c_char`. Passing NULL is a no-op. Never call this
/// on a pointer not returned by this crate, and never call it twice on
/// the same pointer (standard `CString::into_raw`/`from_raw` contract).
///
/// # Safety
/// `ptr` must either be NULL or a pointer previously returned by a
/// `yadorilink_fp_*` function in this crate, not yet freed.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_fp_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(|| {
        drop(CString::from_raw(ptr));
    });
}

/// Returns the real user home directory (the `~/Library/
/// CloudStorage/yadorilink/<group-name>` managed-path computation needs
/// this — see `ipc_client::real_home_dir_string`'s doc comment for why
/// it's resolved via `getpwuid(3)` rather than Foundation APIs even
/// though the host app calling this is itself unsandboxed today).
/// Caller must free with `yadorilink_fp_free_string`.
#[no_mangle]
pub extern "C" fn yadorilink_fp_real_home_dir() -> *mut c_char {
    let result = catch_unwind(|| CString::new(ipc_client::real_home_dir_string()).ok());
    match result {
        Ok(Some(s)) => s.into_raw(),
        _ => CString::new("").unwrap().into_raw(),
    }
}

/// Lists every OnDemand-linked folder group known to the daemon, as a
/// JSON array of `{"local_path":..., "group_id":...}` objects (used for
/// the domain-discovery call). Empty JSON array (`"[]"`) on any
/// failure — never blocks past `ipc_client`'s enumeration timeout, never
/// panics across the FFI boundary. Caller must free with
/// `yadorilink_fp_free_string`.
#[no_mangle]
pub extern "C" fn yadorilink_fp_list_on_demand_folders() -> *mut c_char {
    let result = catch_unwind(ipc_client::list_on_demand_folders);
    match result {
        Ok(folders) => to_c_json(&folders, "[]"),
        Err(_) => CString::new("[]").unwrap().into_raw(),
    }
}

/// Lists every (non-deleted) file in the folder group rooted at
/// `local_path`, as a JSON array of `{"relative_path", "size",
/// "mtime_unix_nanos", "materialization_state"}` objects (used as the
/// `NSFileProviderEnumerator` data source). Empty JSON array on a null
/// path or any failure. Caller must free with `yadorilink_fp_free_string`.
///
/// # Safety
/// `local_path` must be a valid, null-terminated C string, or NULL.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_fp_list_folder_files(local_path: *const c_char) -> *mut c_char {
    let Some(local_path) = path_from_c_str(local_path) else {
        return CString::new("[]").unwrap().into_raw();
    };
    let result = catch_unwind(|| ipc_client::list_folder_files(&local_path));
    match result {
        Ok(entries) => to_c_json(&entries, "[]"),
        Err(_) => CString::new("[]").unwrap().into_raw(),
    }
}

/// Queries combined sync/materialization status for `path`, as a JSON
/// object `{"sync_state", "materialization_state"}` (the `item(for:request:
/// completionHandler:)` data source). Falls back to all-"unspecified"
/// JSON on a null path or any failure. Caller must free with
/// `yadorilink_fp_free_string`.
///
/// # Safety
/// `path` must be a valid, null-terminated C string, or NULL.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_fp_query_status(path: *const c_char) -> *mut c_char {
    const FALLBACK: &str = r#"{"sync_state":"unspecified","materialization_state":"unspecified"}"#;
    let Some(path) = path_from_c_str(path) else {
        return CString::new(FALLBACK).unwrap().into_raw();
    };
    let result = catch_unwind(|| ipc_client::query_status(&path));
    match result {
        Ok(info) => to_c_json(&info, FALLBACK),
        Err(_) => CString::new(FALLBACK).unwrap().into_raw(),
    }
}

/// Requests hydration of `path` from the daemon (backs
/// `fetchContents(for:version:request:completionHandler:)`), blocking
/// the calling thread up to `ipc_client`'s `HYDRATION_TIMEOUT` (35s,
/// a bounded-timeout decision). Returns `true` only on a
/// confirmed `HydrateResponse{ok: true}`; `false` for a null path,
/// timeout, unreachable daemon, or a daemon-reported hydration failure —
/// the Swift caller is expected to complete the OS callback with an
/// `NSFileProviderError` (e.g. `.serverUnreachable`) on `false`, never
/// hang the opening application.
///
/// # Safety
/// `path` must be a valid, null-terminated C string, or NULL.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_fp_hydrate(path: *const c_char) -> bool {
    let Some(path) = path_from_c_str(path) else { return false };
    catch_unwind(|| ipc_client::hydrate(&path)).unwrap_or(false)
}
