#![cfg(test)]

use std::cell::RefCell;
use std::process::{ExitStatus, Output};

use super::*;

struct MockRunner {
    stdout: &'static str,
    succeed: bool,
    calls: RefCell<Vec<(String, Vec<String>)>>,
}

#[cfg(unix)]
fn mock_exit_status(succeed: bool) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(if succeed { 0 } else { 1 << 8 })
}
#[cfg(windows)]
fn mock_exit_status(succeed: bool) -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    ExitStatus::from_raw(if succeed { 0 } else { 1 })
}

impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
        self.calls
            .borrow_mut()
            .push((program.to_string(), args.iter().map(|s| s.to_string()).collect()));
        Ok(Output {
            status: mock_exit_status(self.succeed),
            stdout: self.stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    }
}

/// A real file so `canonicalize` succeeds and the mocked `dpkg-query -S`
/// output can be built against the exact resolved path, matching how
/// real dpkg output is keyed.
fn temp_binary() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("yadorilink");
    std::fs::write(&path, b"x").unwrap();
    let canonical = std::fs::canonicalize(&path).unwrap();
    (dir, canonical)
}

#[test]
fn dpkg_owning_the_exact_running_binary_reports_apt() {
    let (_dir, exe) = temp_binary();
    let stdout: &'static str =
        Box::leak(format!("yadorilink: {}\n", exe.display()).into_boxed_str());
    let runner = MockRunner { stdout, succeed: true, calls: RefCell::new(vec![]) };
    assert_eq!(detect_install_source(&runner, &exe), "apt");
    assert_eq!(
        runner.calls.borrow()[0],
        ("dpkg-query".to_string(), vec!["-S".to_string(), exe.to_str().unwrap().to_string(),])
    );
}

#[test]
fn dpkg_not_owning_this_path_reports_standalone() {
    // This is the coexisting-installs case the path-scoping fix
    // targets: a `.deb` may have put a *different* binary at
    // /usr/bin/yadorilink, but dpkg-query -S has no record of *this*
    // path at all (e.g. a standalone tarball extraction under
    // ~/.local/bin), so it exits non-zero ("no path found matching
    // pattern") regardless of whether the yadorilink package is
    // installed somewhere else.
    let (_dir, exe) = temp_binary();
    let runner = MockRunner { stdout: "", succeed: false, calls: RefCell::new(vec![]) };
    assert_eq!(detect_install_source(&runner, &exe), "standalone");
}

#[test]
fn path_owned_by_a_different_package_reports_standalone() {
    let (_dir, exe) = temp_binary();
    let stdout: &'static str =
        Box::leak(format!("some-other-package: {}\n", exe.display()).into_boxed_str());
    let runner = MockRunner { stdout, succeed: true, calls: RefCell::new(vec![]) };
    assert_eq!(detect_install_source(&runner, &exe), "standalone");
}

#[test]
fn missing_dpkg_query_reports_standalone() {
    struct MissingRunner;
    impl CommandRunner for MissingRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> std::io::Result<Output> {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }
    let (_dir, exe) = temp_binary();
    assert_eq!(detect_install_source(&MissingRunner, &exe), "standalone");
}

#[test]
fn nonexistent_exe_falls_back_to_the_given_path_rather_than_erroring() {
    // canonicalize() fails for a path that doesn't exist (a deleted/
    // replaced binary) -- must fall back to the given path, not panic.
    let runner = MockRunner { stdout: "", succeed: false, calls: RefCell::new(vec![]) };
    let missing = Path::new("/nonexistent/path/to/yadorilink");
    assert_eq!(detect_install_source(&runner, missing), "standalone");
    assert_eq!(runner.calls.borrow()[0].1[1], "/nonexistent/path/to/yadorilink");
}
