//! add-automatic-updates task 4.1: macOS install handoff for a verified
//! notarized `.pkg` artifact.
//!
//! Scope note (per this change's own review guidance): this repo's macOS
//! build (`installer/macos/build-pkg.sh`) does not yet ship a privileged
//! helper tool, and today's interim builds are frequently unsigned (a
//! real-signed `.app` inside an unsigned `.pkg`, see that script's header
//! comment). A daemon process running as the logged-in user has no
//! standing privilege to silently run `installer -pkg ... -target /`
//! (that requires root). Rather than inventing a privileged-helper
//! architecture that can't be verified without real Developer ID
//! Installer signing and notarization credentials, this implements the
//! honest, currently-buildable half of design.md's "Daemon-Orchestrated
//! Checks, Installer-Owned Replacement" decision: the daemon hands the
//! verified `.pkg` off to macOS's own Installer.app (`open <pkg>`),
//! which prompts the user for admin credentials itself and performs the
//! actual install — the daemon never overwrites its own running binary
//! and never tries to self-elevate. A future privileged-helper upgrade
//! would change this flow.

use std::path::Path;

use super::verify::CommandRunner;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstallError {
    #[error("artifact does not look like a macOS installer package: {0}")]
    NotAPackage(String),
    #[error("failed to hand off to Installer.app: {0}")]
    HandoffFailed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// `open` successfully launched Installer.app with the artifact
    /// pre-loaded; the user must complete the install themselves (admin
    /// prompt). This is not "installed" — status should reflect that a
    /// handoff is pending, matching the `UpdateInstallResponse` proto
    /// doc comment's `"manual_handoff_required"`-style outcomes.
    HandoffLaunched,
}

/// Hands `artifact_path` off to Installer.app. Requires a `.pkg`
/// extension (this is the only macOS artifact type this repo's build
/// pipeline produces); anything else fails closed rather than guessing.
pub fn install(
    runner: &dyn CommandRunner,
    artifact_path: &Path,
) -> Result<InstallOutcome, InstallError> {
    if artifact_path.extension().and_then(|e| e.to_str()) != Some("pkg") {
        return Err(InstallError::NotAPackage(artifact_path.display().to_string()));
    }
    let path_str = artifact_path.to_string_lossy().to_string();
    let output =
        runner.run("open", &[&path_str]).map_err(|e| InstallError::HandoffFailed(e.to_string()))?;
    if !output.status.success() {
        return Err(InstallError::HandoffFailed(format!(
            "`open {path_str}` exited with status {:?}",
            output.status.code()
        )));
    }
    Ok(InstallOutcome::HandoffLaunched)
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
}
