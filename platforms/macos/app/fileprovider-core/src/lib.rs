//! The "thin Rust core" behind
//! `NSFileProviderReplicatedExtension` (`YadoriLinkFileProvider`), the File
//! Provider extension-point counterpart of `platforms/macos/app/core` (which
//! backs the FinderSync extension point — see this crate's Cargo.toml
//! for why they're separate crates rather than one shared staticlib).
//!
//! Same fail-soft/bounded-timeout/`catch_unwind` contract as `core::lib`:
//! every exported function must never block its caller past the timeout
//! documented in `ipc_client`, and must never let a panic unwind across
//! the FFI boundary (undefined behavior in a staticlib).
//!
//! Lists (folder discovery, provider-root requests and replies) cross the FFI
//! boundary as a single heap-allocated, NUL-terminated JSON C string
//! rather than a C array-of-structs — see Cargo.toml's doc comment for
//! why. Every function that returns `*mut c_char` transfers ownership of
//! that allocation to the caller, who must free it with
//! `yadorilink_fp_free_string` exactly once (never with `free(3)` directly —
//! the allocation was made by Rust's global allocator via `CString`,
//! which is not guaranteed to be `libc`'s `malloc` on every target).

mod host_client;
mod ipc_client;
mod provider_client;

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

/// Lists every provider-backed root known to the daemon, as a JSON array of
/// `{"root_id", "group_id", "display_name", "hydration_policy", "registration_ready"}`
/// objects (`root_id` is the domain identifier; no local path) — the
/// authoritative desired-registration-state snapshot domain reconciliation
/// reconciles against (see `ipc_client::list_provider_folders`'s own doc
/// comment). Returns NULL, deliberately distinct from a valid `"[]"` JSON
/// string, when the daemon could not be reached or the call otherwise
/// failed/panicked — the caller MUST treat NULL as "cannot currently
/// confirm the desired state, do not reconcile (leave existing domain
/// registrations untouched)," never as "the desired state is empty."
/// Collapsing these two cases is exactly the fail-open mistake a
/// snapshot-based reconciliation must not make: a transient daemon
/// hiccup must never be read as "remove every registered domain." Caller
/// must free a non-NULL result with `yadorilink_fp_free_string`.
///
/// `app_group_container` is the app group container path the OS gave this process (NULL or empty: none);
/// the daemon adopts it once as the place of its provider temp root.
///
/// # Safety
/// `app_group_container` must be a valid, null-terminated C string, or NULL.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_fp_list_provider_folders(
    app_group_container: *const c_char,
) -> *mut c_char {
    let container = path_from_c_str(app_group_container).unwrap_or_default();
    let result = catch_unwind(|| ipc_client::list_provider_folders(&container));
    match result {
        Ok(Some(snapshot)) => to_c_json(&snapshot, "{}"),
        Ok(None) | Err(_) => std::ptr::null_mut(),
    }
}

/// One request of the provider-root protocol (JSON in, JSON out; see `provider_client`). Returns
/// NULL on any transport failure (unreachable daemon, timeout, malformed request or reply), which
/// the caller must treat as `.serverUnreachable`, never as an empty result. Free a non-NULL result
/// with `yadorilink_fp_free_string`.
///
/// # Safety
/// `request_json` must be a valid, null-terminated C string, or NULL.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_fp_provider_call(request_json: *const c_char) -> *mut c_char {
    let Some(request) = path_from_c_str(request_json) else { return std::ptr::null_mut() };
    match catch_unwind(|| provider_client::call(&request)) {
        Ok(Some(json)) => CString::new(json).map_or(std::ptr::null_mut(), CString::into_raw),
        _ => std::ptr::null_mut(),
    }
}

/// Opens the host app's persistent connection to the daemon (see `host_client`). Events arrive as
/// JSON text through `callback` on the connection's own thread, with `context` passed back verbatim;
/// the text is valid only for the duration of the call. NULL when the daemon cannot be reached.
/// Close with `yadorilink_fp_host_close`.
///
/// # Safety
/// `context` must be usable from any thread until the host is closed and the last event delivered.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_fp_host_open(
    callback: host_client::EventCallback,
    context: *mut std::ffi::c_void,
) -> *mut host_client::Host {
    match catch_unwind(|| host_client::Host::open(callback, context)) {
        Ok(Some(host)) => Box::into_raw(Box::new(host)),
        _ => std::ptr::null_mut(),
    }
}

/// Queues one command (JSON) on the host connection. `false`: malformed, or the connection ended.
///
/// # Safety
/// `host` must come from `yadorilink_fp_host_open` and not be closed; `command_json` a valid C string.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_fp_host_send(
    host: *mut host_client::Host,
    command_json: *const c_char,
) -> bool {
    let Some(command) = path_from_c_str(command_json) else { return false };
    if host.is_null() {
        return false;
    }
    catch_unwind(|| (*host).send(&command)).unwrap_or(false)
}

/// Releases the host handle (the connection thread ends once its command queue is dropped).
///
/// # Safety
/// `host` must come from `yadorilink_fp_host_open` and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn yadorilink_fp_host_close(host: *mut host_client::Host) {
    if !host.is_null() {
        drop(Box::from_raw(host));
    }
}
