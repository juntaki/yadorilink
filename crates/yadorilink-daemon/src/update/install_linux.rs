//! Linux install-source detection.
//!
//! Unlike macOS/Windows, this repo does not currently ship a self-update
//! *installer* for Linux at all — `manager::dispatch_install` has no
//! artifact-handoff path for `"linux"` (`installer/linux/build-deb.sh`'s
//! `.deb` is the only Linux install target, and there is no
//! `install_linux::install` mirroring `install_macos`/`install_windows`).
//! This module exists purely so `PlatformInfo::install_source` reports the
//! truth on Linux instead of the previous hardcoded `"standalone"` for
//! every non-Windows platform: an update-check request already carries
//! `install_source` (see `docs/AUTOMATIC_UPDATES.md`'s Privacy table), and
//! a future Linux self-update path (or a manifest that stops advertising
//! updates to package-manager-managed installs) needs an honest answer
//! here to build on.
//!
//! Detection uses `dpkg-query -S <path>`, not a marker file this project's
//! own `.deb` would need to write: dpkg already tracks exactly this fact
//! for any package it manages, including installs that predate this
//! detection code, so there is nothing to keep in sync with
//! `installer/linux/debian/postinst`.
//!
//! Crucially, this is scoped to the *exact binary currently running*
//! (`dpkg-query -S <canonicalized current_exe>`), not "is the `yadorilink`
//! package installed anywhere" (`dpkg-query -W yadorilink`, this module's
//! first version). The two differ whenever a `.deb` install and a
//! standalone build coexist on the same machine — e.g. the `.deb` put a
//! binary at `/usr/bin/yadorilink` and a separately extracted release
//! tarball (or a `cargo build` output) is what's actually running from
//! `~/.local/bin`. The `-W` form would report `"apt"` for that standalone
//! binary too, matching `install_windows::detect_install_source(&exe)`'s
//! existing path-scoped precedent instead of dpkg's own package-level
//! query.

use std::path::Path;

use super::verify::CommandRunner;

/// Returns whether `dpkg-query -S <path>` reports `path` as owned by the
/// `yadorilink` package specifically. `path` must already be the exact
/// string `dpkg-query` would report — i.e. canonicalized — since dpkg
/// records the real, symlink-resolved path a package's files were
/// installed to, never a `PATH` symlink that happens to point at one.
fn dpkg_owns_path(runner: &dyn CommandRunner, path: &str) -> bool {
    let Ok(output) = runner.run("dpkg-query", &["-S", path]) else {
        return false;
    };
    if !output.status.success() {
        // Covers both: the path isn't owned by any package (the
        // coexisting-standalone-binary case this scoping exists for), and
        // dpkg-query missing entirely (non-Debian-family distros).
        return false;
    }
    // Each matching line looks like "<pkg>[, <pkg>...]: <path>" (dpkg
    // lists every package via a diversion, comma-separated, before the
    // colon; ordinarily just one).
    String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        line.split_once(':')
            .map(|(pkgs, listed_path)| {
                listed_path.trim() == path && pkgs.split(',').any(|p| p.trim() == "yadorilink")
            })
            .unwrap_or(false)
    })
}

/// `"apt"` when the exact binary currently running (`current_exe`,
/// canonicalized) is a file `dpkg-query -S` reports as owned by the
/// `yadorilink` package, else `"standalone"` — the same two-value shape
/// `install_windows`'s Store-vs-standalone split and `install_macos`'s
/// Homebrew check use, so `manager::PlatformInfo::install_source` stays a
/// plain, stable string across platforms.
///
/// Canonicalization failure (a deleted/replaced binary, or a `current_exe`
/// this process could not resolve at all) falls back to the path as given
/// — `dpkg-query -S` will then simply fail to match it, correctly falling
/// through to `"standalone"` rather than erroring.
pub fn detect_install_source(runner: &dyn CommandRunner, current_exe: &Path) -> String {
    let canonical =
        std::fs::canonicalize(current_exe).unwrap_or_else(|_| current_exe.to_path_buf());
    let Some(path_str) = canonical.to_str() else {
        return "standalone".to_string();
    };
    if dpkg_owns_path(runner, path_str) {
        "apt".to_string()
    } else {
        "standalone".to_string()
    }
}

#[cfg(test)]
mod tests {
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
}
