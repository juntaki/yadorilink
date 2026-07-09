//! add-desktop-status-app task 3.3 "launch-at-login": toggles this app's
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
    // `getuid()` FFI call is a smaller addition than pulling in the whole
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

/// task 4.2 notes an equivalent Windows startup-registration story
/// (mirroring `installer/windows/daemon-task.ps1`'s per-user Scheduled
/// Task) is the natural next step, but this change was implemented and
/// verified only on macOS (this environment has no Windows machine/VM to
/// register a real Scheduled Task against and confirm it fires — the same
/// honesty discipline `installer/windows/`'s own already-existing
/// components note about needing real-VM verification). Left as an
/// explicit `Unsupported` error rather than a silent no-op so a caller
/// can surface "not available on this platform yet" instead of falsely
/// claiming success.
#[cfg(not(target_os = "macos"))]
pub fn enable() -> Result<(), LoginItemError> {
    Err(LoginItemError::Unsupported)
}

#[cfg(not(target_os = "macos"))]
pub fn disable() -> Result<(), LoginItemError> {
    Err(LoginItemError::Unsupported)
}

#[cfg(not(target_os = "macos"))]
pub fn is_enabled() -> bool {
    false
}
