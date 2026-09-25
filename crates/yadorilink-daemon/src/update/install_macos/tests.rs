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
fn non_pkg_artifact_is_rejected() {
    let runner = MockRunner { succeed: true };
    let result = install(&runner, Path::new("/tmp/not-a-package.exe"));
    assert!(matches!(result, Err(InstallError::NotAPackage(_))));
}

#[test]
fn pkg_artifact_launches_handoff() {
    let runner = MockRunner { succeed: true };
    let result = install(&runner, Path::new("/tmp/yadorilink-0.2.0.pkg"));
    assert_eq!(result, Ok(InstallOutcome::HandoffLaunched));
}

#[test]
fn failed_open_is_reported_not_silently_ignored() {
    let runner = MockRunner { succeed: false };
    let result = install(&runner, Path::new("/tmp/yadorilink-0.2.0.pkg"));
    assert!(matches!(result, Err(InstallError::HandoffFailed(_))));
}

#[test]
fn missing_marker_reports_standalone() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("install_source");
    assert_eq!(detect_install_source_at(&marker), "standalone");
}

#[test]
fn homebrew_marker_reports_homebrew() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("install_source");
    std::fs::write(&marker, "homebrew\n").unwrap();
    assert_eq!(detect_install_source_at(&marker), "homebrew");
}

#[test]
fn unrecognized_marker_contents_report_standalone() {
    // A marker file must contain exactly "homebrew" to count -- garbage
    // or a future package-manager name this build doesn't know about
    // must fail closed to "standalone", not be trusted verbatim.
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("install_source");
    std::fs::write(&marker, "not-homebrew").unwrap();
    assert_eq!(detect_install_source_at(&marker), "standalone");
}
