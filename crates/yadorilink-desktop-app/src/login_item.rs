//! Toggles this app's
//! own login-item registration. Mirrors the *mechanism* `installer/macos/
//! scripts/postinstall` already uses for `yadorilink-daemon` itself (a
//! per-user `LaunchAgent` plist under `~/Library/LaunchAgents`, loaded via
//! `launchctl bootstrap gui/$UID`) rather than the newer `SMAppService`
//! API, since that mechanism is already proven end-to-end in this
//! codebase (real-VM-verified per the daemon's own postinstall step) and
//! this app's `Info.plist`/bundle story isn't set up for `SMAppService`'s
//! bundle-identifier-based registration. Windows equivalent (a Scheduled
//! Task, mirroring `installer/windows/daemon-task.ps1`) is not implemented
//! here — see this file's Windows stub for why.

#[derive(Debug, thiserror::Error)]
pub enum LoginItemError {
    #[error("could not determine the current user's home directory")]
    NoHomeDir,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("launch-at-login toggling is not implemented on this platform yet")]
    Unsupported,
}

#[cfg(target_os = "macos")]
mod macos {
    use super::LoginItemError;

    const LABEL: &str = "com.yadorilink.status-app";

    fn plist_path() -> Result<std::path::PathBuf, LoginItemError> {
        let home = std::env::var("HOME").map_err(|_| LoginItemError::NoHomeDir)?;
        Ok(std::path::PathBuf::from(home)
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")))
    }

    /// Registers this app to launch at login, matching the shape of
    /// `installer/macos/scripts/postinstall`'s own daemon plist (`Label`,
    /// `ProgramArguments`, `RunAtLoad`) minus `KeepAlive` — the status app
    /// should relaunch at the next login, not be treated as an essential
    /// service the OS force-restarts if it exits (a user quitting the tray
    /// icon on purpose shouldn't immediately reappear).
    pub fn enable() -> Result<(), LoginItemError> {
        let exe = std::env::current_exe()?;
        let path = plist_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
            exe.display()
        );
        std::fs::write(&path, plist)?;
        let _ = std::process::Command::new("launchctl")
            .args(["bootstrap", &format!("gui/{}", unsafe { libc_getuid() })])
            .arg(&path)
            .status();
        Ok(())
    }

    pub fn disable() -> Result<(), LoginItemError> {
        let path = plist_path()?;
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &format!("gui/{}", unsafe { libc_getuid() })])
            .arg(LABEL)
            .status();
        if path.is_file() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    pub fn is_enabled() -> bool {
        plist_path().map(|p| p.is_file()).unwrap_or(false)
    }

    // `libc` isn't otherwise a dependency of this crate — a single
    // `getuid` FFI call is a smaller addition than pulling in the whole
    // `libc` crate for one syscall already exposed by the platform's libc
    // that every macOS process links against implicitly anyway.
    extern "C" {
        #[link_name = "getuid"]
        fn c_getuid() -> u32;
    }
    unsafe fn libc_getuid() -> u32 {
        c_getuid()
    }
}

#[cfg(target_os = "macos")]
pub use macos::{disable, enable, is_enabled};

/// The Windows launch-at-login
/// toggle. Writes a per-user `HKCU\Software\Microsoft\Windows\CurrentVersion\
/// Run` value pointing at this executable — user-scoped, needs no elevation,
/// and (unlike a machine-wide Scheduled Task) is independently removable. It
/// manages only its own `YadoriLinkStatusApp` value, so it coexists with the
/// installer's own Scheduled-Task startup option without touching it —
/// it reads/writes only its own Run-key value.
///
/// NOTE: cross-compilation to Windows is not available in this environment, so
/// this module is inspection-verified only (the same honesty discipline the
/// `ipc_client.rs` Windows named-pipe path documents); it is `#[cfg(windows)]`
/// so it never affects the macOS build.
#[cfg(target_os = "windows")]
mod windows {
    use super::LoginItemError;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
    use winreg::RegKey;

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const VALUE_NAME: &str = "YadoriLinkStatusApp";

    pub fn enable() -> Result<(), LoginItemError> {
        let exe = std::env::current_exe()?;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        // The Run key exists on every Windows install, but create_subkey is
        // idempotent and returns the existing key if it's already there.
        let (run, _) = hkcu.create_subkey(RUN_KEY)?;
        // A quoted path so a program directory containing spaces still launches
        // as a single argument.
        run.set_value(VALUE_NAME, &format!("\"{}\"", exe.display()))?;
        Ok(())
    }

    pub fn disable() -> Result<(), LoginItemError> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let run = match hkcu.open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_SET_VALUE) {
            Ok(key) => key,
            // No Run key at all ⇒ nothing of ours to remove.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        match run.delete_value(VALUE_NAME) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn is_enabled() -> bool {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        hkcu.open_subkey(RUN_KEY).and_then(|run| run.get_value::<String, _>(VALUE_NAME)).is_ok()
    }
}

#[cfg(target_os = "windows")]
pub use windows::{disable, enable, is_enabled};

/// Any platform other than the two shipped desktop targets (macOS/Windows) has
/// no launch-at-login mechanism here. Left as an explicit `Unsupported` error
/// rather than a silent no-op so a caller can surface "not available on this
/// platform" instead of falsely claiming success (spec: "unsupported platforms
/// SHALL fail explicitly rather than silently").
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn enable() -> Result<(), LoginItemError> {
    Err(LoginItemError::Unsupported)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn disable() -> Result<(), LoginItemError> {
    Err(LoginItemError::Unsupported)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn is_enabled() -> bool {
    false
}
