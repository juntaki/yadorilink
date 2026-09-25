//! Linux install-source detection.
//!
//! Unlike macOS/Windows, this repo does not currently ship a self-update
//! *installer* for Linux at all — `manager::dispatch_install` has no
//! artifact-handoff path for `"linux"` (`installer/linux/build-deb.sh`'s
//! `.deb` is the only Linux install target, and there is no
//! `install_linux::install` mirroring `install_macos`/`install_windows`).
//! This module exists purely so `PlatformInfo::install_source` reports the
//! truth on Linux rather than a hardcoded `"standalone"` for every
//! non-Windows platform: an update-check request carries `install_source`,
//! and
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
mod tests;
