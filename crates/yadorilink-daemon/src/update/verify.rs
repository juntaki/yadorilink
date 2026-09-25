//! Downloaded-artifact verification — SHA-256 checksum (against the
//! signed manifest entry's `artifact_sha256`) and platform
//! publisher-signature verification hooks for macOS and Windows.
//!
//! This is deliberately independent of, and in addition to, the manifest
//! signature check in `manifest::verify_and_parse`: the manifest
//! signature protects metadata (which artifact URL/checksum is claimed
//! for this version); this module protects the artifact bytes
//! themselves, using exactly the same checks this repo's release
//! tooling already performs by hand
//! (`scripts/ci/generate-release-checksums.py`'s SHA-256 sidecar
//! convention, `installer/macos/verify-pkg.sh`'s `pkgutil`/`spctl`
//! checks, `installer/windows/verify-installer.ps1`'s
//! `Get-AuthenticodeSignature` check) — reused here as the fail-closed,
//! automatic gate before an update is ever installed, rather than
//! reinventing a second verification scheme.
//!
//! Every public entry point here is fail-closed: any I/O error, missing
//! tool, non-zero exit, or unexpected output is treated as verification
//! failure, never as "skip this check."

use std::io::Read;
use std::path::Path;
use std::process::Output;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("failed to read artifact: {0}")]
    Io(String),
    #[error("checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("platform signature check failed: {0}")]
    SignatureCheck(String),
}

/// Streams `path` through SHA-256 (matching
/// `scripts/ci/generate-release-checksums.py`'s own `sha256_of` — read in
/// fixed-size chunks rather than loading the whole artifact into memory)
/// and compares against `expected_hex` (case-insensitive, matching that
/// script's own comparison).
pub fn verify_checksum(path: &Path, expected_hex: &str) -> Result<(), VerifyError> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| VerifyError::Io(format!("{}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| VerifyError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hex::encode(hasher.finalize());
    if actual.eq_ignore_ascii_case(expected_hex.trim()) {
        Ok(())
    } else {
        Err(VerifyError::ChecksumMismatch { expected: expected_hex.trim().to_string(), actual })
    }
}

/// Injectable process runner so the platform-signature checks below are
/// unit-testable without a real codesigned/Authenticode-signed artifact
/// or the platform-specific tool on `PATH` — `SystemCommandRunner` is
/// what production code always uses; tests supply a canned-output mock.
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output>;
}

pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
        std::process::Command::new(program).args(args).output()
    }
}

/// macOS platform-signature verification: reuses exactly the
/// checks `installer/macos/verify-pkg.sh` already performs by hand —
/// `pkgutil --check-signature` (any signed status) plus `spctl -a -vvv -t
/// install` (Gatekeeper's own install-time verdict) — and additionally
/// requires the signing authority line to contain `expected_identity`
/// when one is pinned (`ReleaseEntry::artifact_publisher_identity`).
/// Fails closed: a missing tool, a non-zero/unexpected `pkgutil`/`spctl`
/// result, or an identity that doesn't match is always rejected.
///
/// Identity matching: `expected_identity` is matched as a substring of the
/// free-text `Authority:` line (e.g. `Developer ID Installer: Example Corp
/// (TEAMID1234)`), after `pkgutil`/`spctl` have already verified the
/// signature chain itself. The manifest carries no dedicated Team ID field
/// for an exact-match comparison.
pub fn verify_macos_signature(
    runner: &dyn CommandRunner,
    artifact_path: &Path,
    expected_identity: &str,
) -> Result<(), VerifyError> {
    let path_str = artifact_path.to_string_lossy().to_string();

    let pkgutil = runner
        .run("pkgutil", &["--check-signature", &path_str])
        .map_err(|e| VerifyError::SignatureCheck(format!("pkgutil not runnable: {e}")))?;
    if !pkgutil.status.success() {
        return Err(VerifyError::SignatureCheck(
            "pkgutil --check-signature reported no valid signature".to_string(),
        ));
    }
    let pkgutil_out = String::from_utf8_lossy(&pkgutil.stdout);
    if pkgutil_out.to_lowercase().contains("no signature") {
        return Err(VerifyError::SignatureCheck("artifact is unsigned".to_string()));
    }

    let spctl = runner
        .run("spctl", &["-a", "-vvv", "-t", "install", &path_str])
        .map_err(|e| VerifyError::SignatureCheck(format!("spctl not runnable: {e}")))?;
    // spctl prints its verdict to stderr, and exits non-zero for a
    // rejected package — both must indicate acceptance.
    let spctl_out = format!(
        "{}{}",
        String::from_utf8_lossy(&spctl.stdout),
        String::from_utf8_lossy(&spctl.stderr)
    );
    if !spctl.status.success() || !spctl_out.contains("accepted") {
        return Err(VerifyError::SignatureCheck(
            "spctl did not accept the package for install".to_string(),
        ));
    }

    if !expected_identity.is_empty() && !pkgutil_out.contains(expected_identity) {
        return Err(VerifyError::SignatureCheck(format!(
            "signing authority does not contain expected identity {expected_identity:?}"
        )));
    }

    Ok(())
}

/// Windows platform-signature verification: shells out to
/// PowerShell's `Get-AuthenticodeSignature`, mirroring
/// `installer/windows/verify-installer.ps1` exactly, and requires
/// `Status` to be `Valid` plus (when pinned) the signer certificate
/// subject to contain `expected_identity`. Fails closed on any non-`Valid`
/// status, missing PowerShell, or unparseable output.
///
/// The artifact path is never interpolated into the script text: it is
/// passed as a genuine trailing process argument and read inside the
/// script via `$args[0]`, which is PowerShell's own documented idiom
/// for passing untrusted values to `-Command` (see `Get-Help
/// about_PowerShell_exe`). A path containing a single quote, a
/// semicolon, or any other PowerShell-syntax character therefore can
/// never break out of string literal context or be interpreted as
/// script — there is no string literal for it to break out of.
///
/// Identity matching: like `verify_macos_signature`, this matches
/// `expected_identity` as a substring of `SignerCertificate.Subject`; the
/// manifest carries no dedicated certificate-thumbprint field for an
/// exact-match comparison.
pub fn verify_windows_signature(
    runner: &dyn CommandRunner,
    artifact_path: &Path,
    expected_identity: &str,
) -> Result<(), VerifyError> {
    let path_str = artifact_path.to_string_lossy().to_string();
    // `& { ... }` invokes a script block; PowerShell binds any CLI
    // arguments that follow the `-Command` script text to that block's
    // own `$args`, so `path_str` reaches the script as data, never as
    // code -- see the doc comment above.
    const SCRIPT: &str = "& { \
         $sig = Get-AuthenticodeSignature -LiteralPath $args[0]; \
         Write-Output \"STATUS=$($sig.Status)\"; \
         Write-Output \"SUBJECT=$($sig.SignerCertificate.Subject)\" \
         }";
    let output = runner
        .run("powershell", &["-NoProfile", "-Command", SCRIPT, &path_str])
        .map_err(|e| VerifyError::SignatureCheck(format!("powershell not runnable: {e}")))?;
    if !output.status.success() {
        return Err(VerifyError::SignatureCheck("Get-AuthenticodeSignature failed to run".into()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let status = stdout
        .lines()
        .find_map(|l| l.strip_prefix("STATUS="))
        .ok_or_else(|| VerifyError::SignatureCheck("could not parse signature status".into()))?;
    if status.trim() != "Valid" {
        return Err(VerifyError::SignatureCheck(format!(
            "Authenticode signature status is not valid: {}",
            status.trim()
        )));
    }
    if !expected_identity.is_empty() {
        let subject = stdout.lines().find_map(|l| l.strip_prefix("SUBJECT=")).unwrap_or("");
        if !subject.contains(expected_identity) {
            return Err(VerifyError::SignatureCheck(format!(
                "signer subject does not contain expected identity {expected_identity:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
