//! macOS install handoff for a verified
//! notarized `.pkg` artifact.
//!
//! Scope note (per this change's own review guidance): this repo's macOS
//! build (`installer/macos/build-pkg.sh`) does not yet ship a privileged
//! helper tool, and today's interim builds are frequently unsigned (a
//! real-signed `.app` inside an unsigned `.pkg`, see that script's header
//! comment). A daemon process running as the logged-in user has no
//! standing privilege to silently run `installer -pkg... -target /`
//! (that requires root). Rather than inventing a privileged-helper
//! architecture that can't be verified without real Developer ID
//! Installer signing and notarization credentials, this implements the
//! honest, currently-buildable half of the "Daemon-Orchestrated
//! Checks, Installer-Owned Replacement" decision: the daemon hands the
//! verified `.pkg` off to macOS's own Installer.app (`open <pkg>`),
//! which prompts the user for admin credentials itself and performs the
//! actual install — the daemon never overwrites its own running binary
//! and never tries to self-elevate. A future privileged-helper upgrade
//! would change this flow.

use std::path::Path;

use super::verify::CommandRunner;

/// Marker file this project's own Homebrew Cask (`Casks/yadorilink.rb` in
/// the `juntaki/homebrew-yadorilink` tap) writes from a `postflight`
/// block, and removes from an `uninstall`/`zap` block, after driving the
/// exact same signed `.pkg` a manual download would run. Root-owned
/// (Cask `pkg` installs always elevate via `sudo`, same as a manual
/// double-click), so a non-privileged process can only read it, never
/// forge it.
///
/// Unlike the Microsoft Store (a structural, unforgeable path signal) or
/// apt (dpkg already tracks package identity natively), a Homebrew Cask
/// wrapping a `.pkg` has no path- or receipt-based signal: `brew install
/// --cask` and a manual `.pkg` double-click both run `installer -pkg ...
/// -target /` and land the exact same files in the exact same places.
/// This marker, written by the Cask itself rather than by
/// `installer/macos/scripts/postinstall` (which runs identically either
/// way and so cannot distinguish them), is the only reliable signal.
pub const HOMEBREW_MARKER_PATH: &str = "/etc/yadorilink/install_source";

/// `"homebrew"` when the Cask's marker file is present and contains
/// exactly that value, else `"standalone"` — the same shape
/// `install_linux::detect_install_source`/`install_windows`'s
/// Store-vs-standalone split use. A missing file (by far the common
/// case: a manual `.pkg` download, or a build predating this marker) is
/// not an error — it's the default, fully-supported path.
pub fn detect_install_source() -> String {
    detect_install_source_at(Path::new(HOMEBREW_MARKER_PATH))
}

/// Path-parameterized so tests exercise the real file-reading logic
/// against a tempdir path instead of mutating process-wide environment
/// state (this crate's test suite runs multi-threaded; a global env-var
/// override here would race exactly like the scan-hook tests this
/// workspace already isolates for that reason — see
/// `oss-public/.github/workflows/release.yml`'s "Scan-hook lib tests"
/// step).
fn detect_install_source_at(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(contents) if contents.trim() == "homebrew" => "homebrew".to_string(),
        _ => "standalone".to_string(),
    }
}

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
mod tests;
