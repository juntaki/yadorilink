#![cfg(test)]

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;
use std::process::{ExitStatus, Output};

use super::*;

/// Builds a mock success/failure `ExitStatus`. Unix's
/// `ExitStatusExt::from_raw` takes an `i32` packed waitpid-style
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

#[derive(Default)]
struct MockRunner {
    responses: std::collections::HashMap<&'static str, Output>,
    /// Every `(program, args)` this mock was invoked with, in order —
    /// lets a test assert *what was actually passed*, not just what
    /// the canned response was, which is exactly what the
    /// path-with-a-quote regression test below needs to prove.
    calls: std::cell::RefCell<Vec<(String, Vec<String>)>>,
}

impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
        self.calls
            .borrow_mut()
            .push((program.to_string(), args.iter().map(|s| s.to_string()).collect()));
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

/// "Fail-closed" proof #1: a downloaded artifact whose bytes don't
/// match the manifest-declared checksum is genuinely rejected.
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

/// "Fail-closed" proof #2: an unsigned artifact (pkgutil reports
/// "no signature") is rejected outright.
#[test]
fn macos_unsigned_artifact_is_rejected() {
    let mut responses = std::collections::HashMap::new();
    responses.insert("pkgutil", fail_output("Status: no signature"));
    let runner = MockRunner { responses, ..Default::default() };
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
    let runner = MockRunner { responses, ..Default::default() };
    assert!(verify_macos_signature(&runner, Path::new("/tmp/fake.pkg"), "").is_ok());
}

/// A pinned expected identity that doesn't appear in the signing
/// authority is rejected even though the package is otherwise validly
/// signed and Gatekeeper-accepted — this is the "wrong-publisher
/// artifact is refused" case.
#[test]
fn macos_wrong_publisher_identity_is_rejected() {
    let mut responses = std::collections::HashMap::new();
    responses.insert(
        "pkgutil",
        ok_output("Status: signed by a developer certificate\nAuthority: Developer ID Installer: Someone Else (OTHERTEAM)\n"),
    );
    responses.insert("spctl", ok_output("accepted\n"));
    let runner = MockRunner { responses, ..Default::default() };
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
    let runner = MockRunner { responses, ..Default::default() };
    let result = verify_windows_signature(&runner, Path::new("C:\\fake.exe"), "");
    assert!(matches!(result, Err(VerifyError::SignatureCheck(_))));
}

#[test]
fn windows_valid_signature_verifies() {
    let mut responses = std::collections::HashMap::new();
    responses
        .insert("powershell", ok_output("STATUS=Valid\nSUBJECT=CN=Example Corp, O=Example Corp\n"));
    let runner = MockRunner { responses, ..Default::default() };
    assert!(verify_windows_signature(&runner, Path::new("C:\\fake.exe"), "").is_ok());
}

/// The Windows mirror of `macos_wrong_publisher_identity_is_rejected`
/// (the "Windows wrong-publisher artifact is refused" case).
#[test]
fn windows_wrong_publisher_identity_is_rejected() {
    let mut responses = std::collections::HashMap::new();
    responses.insert("powershell", ok_output("STATUS=Valid\nSUBJECT=CN=Someone Else\n"));
    let runner = MockRunner { responses, ..Default::default() };
    let result = verify_windows_signature(&runner, Path::new("C:\\fake.exe"), "CN=Example Corp");
    assert!(matches!(result, Err(VerifyError::SignatureCheck(_))));
}

/// SEC #4 regression: a path containing a single quote (e.g. an
/// artifact filename or config dir derived from a username with an
/// apostrophe) must never be embedded in the PowerShell script text
/// -- it must reach the process as a plain argument, byte for byte,
/// with the fixed script text unchanged. Before this fix, this exact
/// path would have closed the `-LiteralPath '...'` string early and
/// let anything following it be interpreted as PowerShell syntax.
#[test]
fn windows_signature_check_passes_a_quoted_path_as_an_argument_not_script_text() {
    let evil_path = r"C:\Users\O'Brien\AppData\yadorilink\updates\yadorilink'; Remove-Item -Recurse -Force C:\; '.exe";
    let mut responses = std::collections::HashMap::new();
    responses
        .insert("powershell", ok_output("STATUS=Valid\nSUBJECT=CN=Example Corp, O=Example Corp\n"));
    let runner = MockRunner { responses, ..Default::default() };

    let result = verify_windows_signature(&runner, Path::new(evil_path), "");
    assert!(result.is_ok(), "a validly-signed artifact must still verify: {result:?}");

    let calls = runner.calls.borrow();
    assert_eq!(calls.len(), 1);
    let (program, args) = &calls[0];
    assert_eq!(program, "powershell");
    // The evil path must appear as its own literal trailing
    // argument -- never inside the `-Command` script text -- and
    // the script text itself must be the fixed, path-independent
    // string every call uses.
    assert_eq!(args.last().map(String::as_str), Some(evil_path));
    let command_index = args.iter().position(|a| a == "-Command").unwrap();
    let script = &args[command_index + 1];
    assert!(
        !script.contains(evil_path) && !script.contains('\''),
        "script text must not embed the path or contain any quote: {script:?}"
    );
    assert!(script.contains("$args[0]"), "script must read the path via $args[0]: {script:?}");
}
