//! add-automatic-updates task 1.4: downloaded-artifact verification —
//! SHA-256 checksum (against the signed manifest entry's
//! `artifact_sha256`) and platform publisher-signature verification
//! hooks for macOS and Windows.
//!
//! This is deliberately independent of, and in addition to, the manifest
//! signature check in `manifest::verify_and_parse` — design.md's "Signed
//! Manifest Plus Platform Signature" decision: the manifest signature
//! protects metadata (which artifact URL/checksum is claimed for this
//! version); this module protects the artifact bytes themselves, using
//! exactly the same checks this repo's release tooling already performs
//! by hand (`scripts/ci/generate-release-checksums.py`'s SHA-256 sidecar
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

/// macOS platform-signature verification (task 1.4): reuses exactly the
/// checks `installer/macos/verify-pkg.sh` already performs by hand —
/// `pkgutil --check-signature` (any signed status) plus `spctl -a -vvv -t
/// install` (Gatekeeper's own install-time verdict) — and additionally
/// requires the signing authority line to contain `expected_identity`
/// when one is pinned (`ReleaseEntry::artifact_publisher_identity`).
/// Fails closed: a missing tool, a non-zero/unexpected `pkgutil`/`spctl`
/// result, or an identity that doesn't match is always rejected.
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

/// Windows platform-signature verification (task 1.4): shells out to
/// PowerShell's `Get-AuthenticodeSignature`, mirroring
/// `installer/windows/verify-installer.ps1` exactly, and requires
/// `Status` to be `Valid` plus (when pinned) the signer certificate
/// subject to contain `expected_identity`. Fails closed on any non-`Valid`
/// status, missing PowerShell, or unparseable output.
pub fn verify_windows_signature(
    runner: &dyn CommandRunner,
    artifact_path: &Path,
    expected_identity: &str,
) -> Result<(), VerifyError> {
    let path_str = artifact_path.to_string_lossy().to_string();
    let script = format!(
        "$sig = Get-AuthenticodeSignature -LiteralPath '{path_str}'; \
         Write-Output \"STATUS=$($sig.Status)\"; \
         Write-Output \"SUBJECT=$($sig.SignerCertificate.Subject)\""
    );
    let output = runner
        .run("powershell", &["-NoProfile", "-Command", &script])
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
mod tests {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    use super::*;

    /// Builds a mock success/failure `ExitStatus`. Unix's
    /// `ExitStatusExt::from_raw` takes an `i32` packed waitpid()-style
    /// (exit code N is encoded as `N << 8`); Windows' takes the raw
    /// `u32` exit code directly with no packing (see
    /// `std::os::windows::process::ExitStatusExt`) — so this needs a
    /// real per-platform mock, not just a value that happens to compile
    /// on both.
    #[cfg(unix)]
    fn mock_exit_status(succeed: bool) -> ExitStatus {
        ExitStatus::from_raw(if succeed { 0 } else { 1 << 8 })
    }
    #[cfg(windows)]
    fn mock_exit_status(succeed: bool) -> ExitStatus {
        ExitStatus::from_raw(if succeed { 0 } else { 1 })
    }

    fn ok_output(stdout: &str) -> Output {
        Output {
            status: mock_exit_status(true),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn fail_output(stdout: &str) -> Output {
        Output {
            status: mock_exit_status(false),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    struct MockRunner {
        responses: std::collections::HashMap<&'static str, Output>,
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, _args: &[&str]) -> std::io::Result<Output> {
            self.responses
                .get(program)
                .map(|o| Output {
                    status: o.status,
                    stdout: o.stdout.clone(),
                    stderr: o.stderr.clone(),
                })
                .ok_or_else(|| std::io::Error::other("no mock response configured"))
        }
    }

    /// task 1.5 "fail-closed" proof #1: a downloaded artifact whose bytes
    /// don't match the manifest-declared checksum is genuinely rejected.
    #[test]
    fn tampered_artifact_fails_checksum_verification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact.bin");
        std::fs::write(&path, b"totally legitimate update contents").unwrap();

        // The checksum of *different* bytes -- as if the manifest
        // described the real artifact but this download was tampered
        // with or corrupted in transit.
        let mut hasher = Sha256::new();
        hasher.update(b"totally legitimate update contents, TAMPERED");
        let wrong_expected = hex::encode(hasher.finalize());

        let result = verify_checksum(&path, &wrong_expected);
        assert!(matches!(result, Err(VerifyError::ChecksumMismatch { .. })));
    }

    #[test]
    fn matching_checksum_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact.bin");
        std::fs::write(&path, b"real bytes").unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"real bytes");
        let expected = hex::encode(hasher.finalize());
        assert!(verify_checksum(&path, &expected).is_ok());
        // Case-insensitivity, matching scripts/ci/generate-release-checksums.py.
        assert!(verify_checksum(&path, &expected.to_uppercase()).is_ok());
    }

    #[test]
    fn missing_artifact_fails_closed() {
        let result = verify_checksum(Path::new("/nonexistent/path/does-not-exist"), "deadbeef");
        assert!(matches!(result, Err(VerifyError::Io(_))));
    }

    /// task 1.5 "fail-closed" proof #2: an unsigned artifact (pkgutil
    /// reports "no signature") is rejected outright.
    #[test]
    fn macos_unsigned_artifact_is_rejected() {
        let mut responses = std::collections::HashMap::new();
        responses.insert("pkgutil", fail_output("Status: no signature"));
        let runner = MockRunner { responses };
        let result = verify_macos_signature(&runner, Path::new("/tmp/fake.pkg"), "");
        assert!(matches!(result, Err(VerifyError::SignatureCheck(_))));
    }

    #[test]
    fn macos_signed_and_gatekeeper_accepted_artifact_verifies() {
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "pkgutil",
            ok_output("package-path: /tmp/fake.pkg\nStatus: signed by a developer certificate issued by Apple for distribution\nAuthority: Developer ID Installer: Example Corp (TEAMID1234)\n"),
        );
        responses
            .insert("spctl", ok_output("/tmp/fake.pkg: accepted\nsource=Notarized Developer ID\n"));
        let runner = MockRunner { responses };
        assert!(verify_macos_signature(&runner, Path::new("/tmp/fake.pkg"), "").is_ok());
    }

    /// A pinned expected identity that doesn't appear in the signing
    /// authority is rejected even though the package is otherwise validly
    /// signed and Gatekeeper-accepted — this is the "wrong-publisher
    /// artifact is refused" case from tasks.md 4.4.
    #[test]
    fn macos_wrong_publisher_identity_is_rejected() {
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "pkgutil",
            ok_output("Status: signed by a developer certificate\nAuthority: Developer ID Installer: Someone Else (OTHERTEAM)\n"),
        );
        responses.insert("spctl", ok_output("accepted\n"));
        let runner = MockRunner { responses };
        let result = verify_macos_signature(
            &runner,
            Path::new("/tmp/fake.pkg"),
            "Developer ID Installer: Example Corp (TEAMID1234)",
        );
        assert!(matches!(result, Err(VerifyError::SignatureCheck(_))));
    }

    #[test]
    fn windows_invalid_signature_status_is_rejected() {
        let mut responses = std::collections::HashMap::new();
        responses.insert("powershell", ok_output("STATUS=NotSigned\nSUBJECT=\n"));
        let runner = MockRunner { responses };
        let result = verify_windows_signature(&runner, Path::new("C:\\fake.exe"), "");
        assert!(matches!(result, Err(VerifyError::SignatureCheck(_))));
    }

    #[test]
    fn windows_valid_signature_verifies() {
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "powershell",
            ok_output("STATUS=Valid\nSUBJECT=CN=Example Corp, O=Example Corp\n"),
        );
        let runner = MockRunner { responses };
        assert!(verify_windows_signature(&runner, Path::new("C:\\fake.exe"), "").is_ok());
    }

    /// The Windows mirror of `macos_wrong_publisher_identity_is_rejected`
    /// (tasks.md 4.4's "Windows wrong-publisher artifact is refused").
    #[test]
    fn windows_wrong_publisher_identity_is_rejected() {
        let mut responses = std::collections::HashMap::new();
        responses.insert("powershell", ok_output("STATUS=Valid\nSUBJECT=CN=Someone Else\n"));
        let runner = MockRunner { responses };
        let result =
            verify_windows_signature(&runner, Path::new("C:\\fake.exe"), "CN=Example Corp");
        assert!(matches!(result, Err(VerifyError::SignatureCheck(_))));
    }
}
