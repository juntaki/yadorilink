//! Windows install source detection (Microsoft Store vs. standalone)
//! and the standalone signed-installer handoff.
//!
//! **Not yet verified against a real Windows machine** — unlike
//! `control_socket.rs`'s `windows_transport` module (explicitly verified
//! on a real Windows 11 VM), this code has only been checked for
//! compiling/unit-testable logic on this development machine (macOS).
//! This remains an open verification item before this path ships in a
//! release build — being honest about what's actually
//! buildable/testable here versus aspirational.

use std::path::Path;

use super::verify::CommandRunner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallSource {
    Standalone,
    MicrosoftStore,
}

impl InstallSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            InstallSource::Standalone => "standalone",
            InstallSource::MicrosoftStore => "microsoft_store",
        }
    }
}

/// Detects whether the currently-running executable was installed via
/// the Microsoft Store (MSIX packages are placed under
/// `%ProgramFiles%\WindowsApps\...` regardless of the app's own install
/// logic) or is a standalone install (this repo's Inno Setup
/// `%ProgramFiles%\yadorilink\` layout). Spec "Microsoft Store install
/// delegates update": a Store install must never fetch or run a
/// standalone installer, so this detection gates that entirely — see
/// `manager::install_now`'s dispatch.
///
/// This repo does not currently produce an MSIX/Store package
/// (`installer/windows/verify-installer.ps1`'s own documented gap), so in
/// practice every real build today detects as `Standalone`; this function
/// exists so that gap is a detection question answered at runtime, not an
/// assumption baked into the update flow that would need revisiting once
/// Store distribution exists.
pub fn detect_install_source(current_exe_path: &Path) -> InstallSource {
    let path_str = current_exe_path.to_string_lossy();
    if path_str.contains("WindowsApps") {
        InstallSource::MicrosoftStore
    } else {
        InstallSource::Standalone
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstallError {
    #[error("standalone installer handoff is not applicable to a Microsoft Store install")]
    StoreManaged,
    #[error("artifact does not look like a Windows installer: {0}")]
    NotAnInstaller(String),
    #[error("installer process failed to launch: {0}")]
    LaunchFailed(String),
    #[error("installer exited with a failure status: {0:?}")]
    InstallerFailed(Option<i32>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    Installed,
}

/// Runs the signed standalone Windows installer in silent update mode
/// (Inno Setup's standard `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`
/// flags — the same installer `installer/windows/yadorilink.iss`
/// produces). `PrivilegesRequired=admin` in that script means Windows
/// will prompt for elevation when this spawns, exactly like a
/// user-initiated re-run of the installer would; this deliberately does
/// not try to suppress or auto-approve that prompt. Waits synchronously
/// for the installer to exit and reports its exit status rather than
/// assuming success — spec's "failed installer leaves current version
/// usable" needs an honest answer here, not a fire-and-forget launch.
///
/// Fails closed if `source` is `MicrosoftStore` — never runs a
/// standalone installer over a Store-managed install.
pub fn install(
    runner: &dyn CommandRunner,
    source: InstallSource,
    artifact_path: &Path,
) -> Result<InstallOutcome, InstallError> {
    if source == InstallSource::MicrosoftStore {
        return Err(InstallError::StoreManaged);
    }
    if artifact_path.extension().and_then(|e| e.to_str()) != Some("exe") {
        return Err(InstallError::NotAnInstaller(artifact_path.display().to_string()));
    }
    let path_str = artifact_path.to_string_lossy().to_string();
    let output = runner
        .run(&path_str, &["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"])
        .map_err(|e| InstallError::LaunchFailed(e.to_string()))?;
    if !output.status.success() {
        return Err(InstallError::InstallerFailed(output.status.code()));
    }
    Ok(InstallOutcome::Installed)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    use super::*;

    /// Builds a mock `ExitStatus` for success/failure test fixtures.
    /// Unix's `ExitStatusExt::from_raw` takes an `i32` packed
    /// waitpid()-style (exit code N is encoded as `N << 8`); Windows'
    /// takes the raw `u32` exit code directly with no packing (see
    /// `std::os::windows::process::ExitStatusExt`) — so this needs a real
    /// per-platform mock, not just a value that happens to compile on
    /// both.
    #[cfg(unix)]
    fn mock_exit_status(succeed: bool) -> ExitStatus {
        ExitStatus::from_raw(if succeed { 0 } else { 1 << 8 })
    }
    #[cfg(windows)]
    fn mock_exit_status(succeed: bool) -> ExitStatus {
        ExitStatus::from_raw(if succeed { 0 } else { 1 })
    }

    struct MockRunner {
        succeed: bool,
    }
    impl CommandRunner for MockRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> std::io::Result<Output> {
            Ok(Output {
                status: mock_exit_status(self.succeed),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    #[test]
    fn windowsapps_path_detects_as_store() {
        let source = detect_install_source(Path::new(
            r"C:\Program Files\WindowsApps\Yadorilink_1.0\yadorilink.exe",
        ));
        assert_eq!(source, InstallSource::MicrosoftStore);
    }

    #[test]
    fn program_files_path_detects_as_standalone() {
        let source =
            detect_install_source(Path::new(r"C:\Program Files\yadorilink\yadorilink.exe"));
        assert_eq!(source, InstallSource::Standalone);
    }

    /// "Store install never runs standalone installer" —
    /// even with a perfectly valid installer artifact, a detected Store
    /// install must refuse to run it.
    #[test]
    fn store_managed_install_never_runs_standalone_installer() {
        let runner = MockRunner { succeed: true };
        let result =
            install(&runner, InstallSource::MicrosoftStore, Path::new(r"C:\update\setup.exe"));
        assert_eq!(result, Err(InstallError::StoreManaged));
    }

    #[test]
    fn standalone_install_runs_the_installer_silently() {
        let runner = MockRunner { succeed: true };
        let result = install(&runner, InstallSource::Standalone, Path::new(r"C:\update\setup.exe"));
        assert_eq!(result, Ok(InstallOutcome::Installed));
    }

    /// "failed installer leaves current version usable" —
    /// this crate's own responsibility here is just to report the
    /// failure honestly rather than claim success.
    #[test]
    fn failed_installer_is_reported_as_a_failure() {
        let runner = MockRunner { succeed: false };
        let result = install(&runner, InstallSource::Standalone, Path::new(r"C:\update\setup.exe"));
        assert!(matches!(result, Err(InstallError::InstallerFailed(_))));
    }
}
