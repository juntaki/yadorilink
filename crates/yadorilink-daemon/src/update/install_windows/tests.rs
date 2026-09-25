#![cfg(test)]

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;
use std::process::{ExitStatus, Output};

use super::*;

/// Builds a mock `ExitStatus` for success/failure test fixtures.
/// Unix's `ExitStatusExt::from_raw` takes an `i32` packed
/// waitpid-style (exit code N is encoded as `N << 8`); Windows'
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
    let source = detect_install_source(Path::new(r"C:\Program Files\yadorilink\yadorilink.exe"));
    assert_eq!(source, InstallSource::Standalone);
}

/// "Store install never runs standalone installer" —
/// even with a perfectly valid installer artifact, a detected Store
/// install must refuse to run it.
#[test]
fn store_managed_install_never_runs_standalone_installer() {
    let runner = MockRunner { succeed: true };
    let result = install(&runner, InstallSource::MicrosoftStore, Path::new(r"C:\update\setup.exe"));
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
