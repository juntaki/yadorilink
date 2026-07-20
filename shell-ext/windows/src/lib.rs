//! A pure-Rust `windows-rs` COM
//! implementation of `IShellIconOverlayIdentifier` for Windows Explorer's
//! icon-overlay system (the first-choice approach, before
//! falling back to a C++/COM shim if this proves unstable).
//!
//! This crate is a shell extension DLL, loaded into every Explorer.exe
//! process — it must never touch the network or storage directly (spec
//! "Shell Extension to Sync Daemon Communication"), only the local IPC
//! channel (`ipc_client`), and must fail soft (no overlay, never an
//! error dialog or a hang) whenever the daemon isn't reachable.

mod context_menu;
// `pub` so the `yadorilink-cfapi-host` binary
// target (see Cargo.toml's doc comment on `[[bin]]`) can reuse the same
// IPC client/cfapi wrapper code via this crate's `rlib` output, instead
// of duplicating the shell-IPC protocol handling in a second place.
pub mod cfapi;
pub mod ipc_client;
mod overlay;
mod registration;

use windows::core::{IUnknown, Interface, Result, GUID, HRESULT};
use windows::Win32::Foundation::{BOOL, CLASS_E_CLASSNOTAVAILABLE, E_NOINTERFACE, S_FALSE, S_OK};
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};

pub use context_menu::ContextMenuHandler;
pub use overlay::{
    ErrorOverlay, OnlineOnlyOverlay, OpenElsewhereOverlay, SyncedOverlay, SyncingOverlay,
};

/// Shared class factory: `pwszpath`-free construction is enough for every
/// overlay identifier here, since each is a stateless singleton that just
/// queries the daemon per call — no per-instance configuration is needed.
#[windows::core::implement(IClassFactory)]
struct ClassFactory {
    clsid: GUID,
}

impl IClassFactory_Impl for ClassFactory_Impl {
    fn CreateInstance(
        &self,
        outer: Option<&IUnknown>,
        iid: *const GUID,
        object: *mut *mut core::ffi::c_void,
    ) -> Result<()> {
        if outer.is_some() {
            return Err(windows::Win32::Foundation::CLASS_E_NOAGGREGATION.into());
        }
        unsafe {
            *object = std::ptr::null_mut;
            let unknown: IUnknown = match self.clsid {
                overlay::CLSID_SYNCED => SyncedOverlay::new().into(),
                overlay::CLSID_SYNCING => SyncingOverlay::new().into(),
                overlay::CLSID_ERROR => ErrorOverlay::new().into(),
                overlay::CLSID_ONLINE_ONLY => OnlineOnlyOverlay::new().into(),
                overlay::CLSID_OPEN_ELSEWHERE => OpenElsewhereOverlay::new().into(),
                context_menu::CLSID_CONTEXT_MENU => ContextMenuHandler::new().into(),
                _ => return Err(CLASS_E_CLASSNOTAVAILABLE.into()),
            };
            unknown.query(&*iid, object).ok()
        }
    }

    fn LockServer(&self, _flock: BOOL) -> Result<()> {
        Ok(())
    }
}

/// # Safety
/// Standard COM DLL export contract: called by the COM subsystem with
/// valid pointers per the documented `DllGetClassObject` ABI.
#[no_mangle]
unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut core::ffi::c_void,
) -> HRESULT {
    if rclsid.is_null() || riid.is_null() || ppv.is_null() {
        return E_NOINTERFACE;
    }
    let clsid = *rclsid;
    if !overlay::is_known_clsid(clsid) && clsid != context_menu::CLSID_CONTEXT_MENU {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    let factory: IClassFactory = ClassFactory { clsid }.into();
    match factory.query(&*riid, ppv).ok() {
        Ok(()) => S_OK,
        Err(e) => e.code(),
    }
}

/// # Safety
/// Standard COM DLL export contract.
#[no_mangle]
unsafe extern "system" fn DllCanUnloadNow() -> HRESULT {
    // Every overlay object here is stateless and short-lived per call —
    // never pin the DLL in memory.
    S_OK
}

/// # Safety
/// Standard COM DLL export contract, called by regsvr32.exe.
#[no_mangle]
unsafe extern "system" fn DllRegisterServer() -> HRESULT {
    match registration::register_all() {
        Ok(()) => S_OK,
        Err(_) => S_FALSE,
    }
}

/// # Safety
/// Standard COM DLL export contract, called by `regsvr32.exe /u`.
#[no_mangle]
unsafe extern "system" fn DllUnregisterServer() -> HRESULT {
    match registration::unregister_all() {
        Ok(()) => S_OK,
        Err(_) => S_FALSE,
    }
}
