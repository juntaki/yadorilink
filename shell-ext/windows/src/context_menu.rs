//! A classic `IContextMenu` handler (shows
//! under Explorer's "Show more options" on Windows 11's default menu,
//! or as a primary entry pre-11/with the classic-menu policy) exposing
//! View Status / Pause / Resume / Pin / Evict, calling
//! `ipc_client::send_context_action` for the same daemon operations
//! `yadorilink pin`/`yadorilink evict`/etc. (control_socket) already expose to
//! the CLI. Registered per-file-type as `*\shellex\ContextMenuHandlers`,
//! matching the on-demand-sync spec's "Context Menu Actions Include Pin
//! and Evict".

use std::sync::Mutex;

use windows::core::{implement, Error, Result, GUID, HRESULT, PCWSTR, PSTR};
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::Com::{IDataObject, DVASPECT_CONTENT, FORMATETC, TYMED_HGLOBAL};
use windows::Win32::UI::Shell::{
    DragFinish, DragQueryFileW, IContextMenu, IContextMenu_Impl, IShellExtInit, IShellExtInit_Impl,
    CMINVOKECOMMANDINFO, HDROP,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, InsertMenuW, HMENU, MF_BYPOSITION, MF_SEPARATOR, MF_STRING,
};
use yadorilink_ipc_proto::shellipc::ContextAction;

pub const CLSID_CONTEXT_MENU: GUID = GUID::from_u128(0x8f3a1c00_1e6b_4b7a_9d2e_1a2b3c4d5e10);

/// Command indices offered by `QueryContextMenu`, relative to
/// `idCmdFirst` — the order here also determines menu display order.
#[derive(Clone, Copy, PartialEq)]
enum Command {
    ViewStatus = 0,
    Pause = 1,
    Resume = 2,
    Pin = 3,
    Evict = 4,
    /// Per the shell-integration spec's "Shell Actions Can Open Desktop
    /// Status App": kept out of `COMMANDS` below since it's a pure UI
    /// action (spawns a companion process) rather
    /// than a daemon `ContextAction` — see `QueryContextMenu`/
    /// `InvokeCommand`'s special-cased handling of this id.
    OpenStatusApp = 5,
}

const COMMANDS: [(Command, &str, ContextAction); 5] = [
    (Command::ViewStatus, "View yadorilink sync status", ContextAction::ViewStatus),
    (Command::Pause, "Pause yadorilink sync for this item", ContextAction::PauseItem),
    (Command::Resume, "Resume yadorilink sync for this item", ContextAction::ResumeItem),
    (Command::Pin, "Pin (keep hydrated)", ContextAction::PinItem),
    (Command::Evict, "Evict (free disk space)", ContextAction::EvictItem),
];

/// the status app binary's install location, mirroring how
/// `installer/windows/yadorilink.iss` installs `yadorilink.exe`/
/// `yadorilink-daemon.exe` flat into `{app}` (`%ProgramFiles%\yadorilink`).
const STATUS_APP_EXE_NAME: &str = "yadorilink-status-app.exe";

/// Resolves the status app binary next to this DLL's own install
/// location — the shell extension DLL and the status app exe are staged
/// into the same `{app}` directory by the installer (`yadorilink.iss`'s
/// `[Files]` section), so "next to this DLL" is the same install root
/// without needing a registry lookup.
fn status_app_path() -> Option<std::path::PathBuf> {
    let dll_path = crate::registration::dll_path().ok()?;
    let dir = std::path::Path::new(&dll_path).parent()?;
    let candidate = dir.join(STATUS_APP_EXE_NAME);
    candidate.is_file().then_some(candidate)
}

fn query_context_menu_result(command_count: u32) -> Result<()> {
    if command_count == 0 {
        Ok(())
    } else {
        // IContextMenu::QueryContextMenu reports the number of command IDs
        // consumed as MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_NULL, count).
        // windows-rs' generated trait shape is Result<>, so the only way
        // to preserve a non-S_OK success HRESULT through the COM vtable shim
        // is to carry that HRESULT in the Error slot.
        Err(Error::from_hresult(HRESULT(command_count as i32)))
    }
}

#[implement(IShellExtInit, IContextMenu)]
pub struct ContextMenuHandler {
    file_path: Mutex<Option<String>>,
}

impl ContextMenuHandler {
    pub fn new() -> Self {
        Self { file_path: Mutex::new(None) }
    }
}

impl Default for ContextMenuHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl IShellExtInit_Impl for ContextMenuHandler_Impl {
    fn Initialize(
        &self,
        _pidlfolder: *const windows::Win32::UI::Shell::Common::ITEMIDLIST,
        pdtobj: Option<&IDataObject>,
        _hkeyprogid: windows::Win32::System::Registry::HKEY,
    ) -> Result<()> {
        let Some(data_object) = pdtobj else { return Ok(()) };
        let format = FORMATETC {
            cfFormat: 15, // CF_HDROP
            ptd: std::ptr::null_mut(),
            dwAspect: DVASPECT_CONTENT.0,
            lindex: -1,
            tymed: TYMED_HGLOBAL.0 as u32,
        };
        unsafe {
            let Ok(medium) = data_object.GetData(&format) else { return Ok(()) };
            let hdrop = HDROP(medium.u.hGlobal.0);
            let mut buf = [0u16; MAX_PATH as usize];
            let len = DragQueryFileW(hdrop, 0, Some(&mut buf));
            if len > 0 {
                *self.file_path.lock().unwrap() =
                    Some(String::from_utf16_lossy(&buf[..len as usize]));
            }
            DragFinish(hdrop);
        }
        Ok(())
    }
}

impl IContextMenu_Impl for ContextMenuHandler_Impl {
    fn QueryContextMenu(
        &self,
        hmenu: HMENU,
        indexmenu: u32,
        idcmdfirst: u32,
        _idcmdlast: u32,
        uflags: u32,
    ) -> Result<()> {
        // CMF_DEFAULTONLY (0x0001) — Explorer is asking only for the
        // default double-click action, which this handler doesn't
        // provide; contribute nothing.
        if uflags & 0x0001 != 0 {
            return query_context_menu_result(0);
        }
        unsafe {
            let mut position = indexmenu;
            let _ = InsertMenuW(hmenu, position, MF_SEPARATOR | MF_BYPOSITION, 0, PCWSTR::null());
            position += 1;
            for (cmd, label, _) in COMMANDS {
                let wide: Vec<u16> = format!("yadorilink: {label}")
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                let _ = AppendMenuW(
                    hmenu,
                    MF_STRING,
                    (idcmdfirst + cmd as u32) as usize,
                    PCWSTR::from_raw(wide.as_ptr()),
                );
                let _ = position; // position tracking only matters for InsertMenuW above
            }
            // Appended after the daemon actions above, same
            // "yadorilink: " label prefix convention.
            // Not part of `COMMANDS` — see `Command::OpenStatusApp`'s doc
            // comment.
            let wide: Vec<u16> =
                "yadorilink: Open Status".encode_utf16().chain(std::iter::once(0)).collect();
            let _ = AppendMenuW(
                hmenu,
                MF_STRING,
                (idcmdfirst + Command::OpenStatusApp as u32) as usize,
                PCWSTR::from_raw(wide.as_ptr()),
            );
        }
        let command_count = Command::OpenStatusApp as u32 + 1;
        query_context_menu_result(command_count)
    }

    fn InvokeCommand(&self, pici: *const CMINVOKECOMMANDINFO) -> Result<()> {
        let Some(path) = self.file_path.lock().unwrap().clone() else { return Ok(()) };
        unsafe {
            let info = &*pici;
            // `lpVerb` is either an integer command offset (low-order
            // word, when the high-order word is zero) or a string verb —
            // this handler only ever registers integer offsets.
            if (info.lpVerb.0 as usize) > 0xFFFF {
                return Ok(());
            }
            let cmd_offset = info.lpVerb.0 as usize as u32;
            if cmd_offset == Command::OpenStatusApp as u32 {
                // A pure UI action (spawn a companion process), not a
                // daemon `ContextAction` — see
                // `Command::OpenStatusApp`'s doc comment. Fails soft: a
                // missing/unlaunchable status app never surfaces an error
                // to Explorer (shell-integration spec's "App is
                // unavailable" scenario), matching the fire-and-forget
                // discipline just below for the daemon-IPC actions.
                if let Some(exe) = status_app_path() {
                    let _ = std::process::Command::new(exe).arg(&path).spawn();
                }
                return Ok(());
            }
            if let Some((_, _, action)) = COMMANDS.iter().find(|(c, _, _)| *c as u32 == cmd_offset)
            {
                // Fire-and-forget: Explorer's context menu invocation is
                // not the place to block on IPC or show a result dialog —
                // matches the shell extension's fail-soft contract
                // elsewhere (a failed action just silently doesn't apply).
                let _ = crate::ipc_client::send_context_action(&path, *action);
            }
        }
        Ok(())
    }

    fn GetCommandString(
        &self,
        _idcmd: usize,
        _uflags: u32,
        _preserved: *const u32,
        _pszname: PSTR,
        _cchmax: u32,
    ) -> Result<()> {
        Ok(())
    }
}
