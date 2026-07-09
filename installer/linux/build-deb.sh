#!/bin/bash
#
# installer/linux/build-deb.sh
#
# Builds a Debian .deb package for yadorilink:
#   - crates/yadorilink-cli        -> /usr/bin/yadorilink
#   - crates/yadorilink-daemon     -> /usr/bin/yadorilink-daemon
#   - systemd/yadorilink-daemon.service (the relevant behavior)
#                                  -> /usr/lib/systemd/user/yadorilink-daemon.service
#   - LICENSE-MIT                  -> /usr/share/doc/yadorilink/
#
# yadorilink-desktop-app (the GTK tray app) and yadorilink-sign-manifest
# (a maintainer-only offline signing tool, see yadorilink-daemon's
# Cargo.toml) are deliberately NOT built or packaged here -- Linux support
# is intentionally scoped to the CLI + daemon only. No GTK/appindicator
# system packages are required to
# build or run this package as a result.
#
# HAND-AUTHORED CONTROL FILE + dpkg-deb, NOT cargo-deb -- see
# installer/linux/README.md's "Packaging approach" section for the full
# rationale; in short: mirrors how installer/macos and installer/windows
# are both hand-authored today, and keeps every packaging decision in
# this directory instead of scattering [package.metadata.deb] into
# crates/yadorilink-cli/Cargo.toml and crates/yadorilink-daemon/Cargo.toml
# (shared files this change's other task groups may be editing at the
# same time).
#
# Requires, on the build machine (a real Linux machine or CI runner --
# this script is not (and cannot be, from this project's macOS dev
# environment) verified to produce a real, installable package; see
# README.md's "What has and hasn't been verified" section):
#   - Rust/cargo, for `cargo build --release`
#   - dpkg-deb (Debian/Ubuntu: part of the base `dpkg` package, always
#     present)
#
# Usage:
#   ./build-deb.sh
#   PKG_VERSION=0.1.0 PKG_ARCH=arm64 ./build-deb.sh
#   YADORILINK_BIN_DIR=/path/to/target/release ./build-deb.sh   # skip cargo build, use prebuilt binaries

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

STAGE_DIR="$SCRIPT_DIR/.stage"
OUT_DIR="$SCRIPT_DIR/dist"

log() { echo "[build-deb] $*"; }

# --- Version + architecture -------------------------------------------------
# Version comes from the workspace's [workspace.package] table (the first
# `version = "..."` line in the root Cargo.toml) unless overridden.
if [ -n "${PKG_VERSION:-}" ]; then
    VERSION="$PKG_VERSION"
else
    VERSION="$(awk -F'"' '/^version = /{print $2; exit}' "$REPO_ROOT/Cargo.toml")"
fi
if [ -z "$VERSION" ]; then
    log "ERROR: could not determine package version from $REPO_ROOT/Cargo.toml; set PKG_VERSION"
    exit 1
fi

if [ -n "${PKG_ARCH:-}" ]; then
    ARCH="$PKG_ARCH"
else
    case "$(uname -m)" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            log "ERROR: unrecognized architecture '$(uname -m)'; set PKG_ARCH explicitly (e.g. amd64, arm64)"
            exit 1
            ;;
    esac
fi

log "Building yadorilink ${VERSION} (${ARCH})"

# --- 1. Build (or locate) the two binaries ---------------------------------
if [ -n "${YADORILINK_BIN_DIR:-}" ]; then
    BIN_DIR="$YADORILINK_BIN_DIR"
    log "Using prebuilt binaries from $BIN_DIR (skipping cargo build)"
else
    log "Running cargo build --release (workspace, excluding yadorilink-desktop-app)..."
    (
        cd "$REPO_ROOT"
        cargo build --release \
            --workspace --exclude yadorilink-desktop-app \
            --bin yadorilink --bin yadorilink-daemon
    )
    BIN_DIR="$REPO_ROOT/target/release"
fi

CLI_BIN="$BIN_DIR/yadorilink"
DAEMON_BIN="$BIN_DIR/yadorilink-daemon"

for bin in "$CLI_BIN" "$DAEMON_BIN"; do
    if [ ! -f "$bin" ]; then
        log "ERROR: expected binary not found: $bin"
        exit 1
    fi
done

# --- 2. Stage the package tree ----------------------------------------------
rm -rf "$STAGE_DIR"
mkdir -p \
    "$STAGE_DIR/DEBIAN" \
    "$STAGE_DIR/usr/bin" \
    "$STAGE_DIR/usr/lib/systemd/user" \
    "$STAGE_DIR/usr/share/doc/yadorilink"

install -m 755 "$CLI_BIN" "$STAGE_DIR/usr/bin/yadorilink"
install -m 755 "$DAEMON_BIN" "$STAGE_DIR/usr/bin/yadorilink-daemon"

# Strip debug symbols from the installed copies (not the build's own
# target/release binaries) -- a release cargo build does not strip by
# default, and lintian's unstripped-binary-or-object check treats an
# unstripped binary in a shipped package as an error, not just a style
# nit (it bloats the package and ships symbols/paths that don't need to
# be public). `strip` is part of binutils, already present on any
# machine that can build this package.
strip "$STAGE_DIR/usr/bin/yadorilink" "$STAGE_DIR/usr/bin/yadorilink-daemon"

install -m 644 "$SCRIPT_DIR/systemd/yadorilink-daemon.service" \
    "$STAGE_DIR/usr/lib/systemd/user/yadorilink-daemon.service"
install -m 644 "$REPO_ROOT/LICENSE-MIT" "$STAGE_DIR/usr/share/doc/yadorilink/LICENSE-MIT"
install -m 644 "$SCRIPT_DIR/debian/copyright" "$STAGE_DIR/usr/share/doc/yadorilink/copyright"

# Debian policy requires a changelog for every package -- for a "native"
# package (no separate upstream tarball, which is what a single-repo Rust
# project packaged this way is), that's debian/changelog rather than
# upstream's own changelog; lintian's no-changelog check treats a missing
# one as an error. Generated here (not a static file in debian/) since it
# must reflect $VERSION, which can be overridden per build (PKG_VERSION)
# -- this project's real release history lives in git, not in a
# hand-maintained changelog file.
{
    echo "yadorilink (${VERSION}) unstable; urgency=low"
    echo
    echo "  * See the project's git history for release notes."
    echo
    echo " -- yadorilink project <juntaki@users.noreply.github.com>  $(date -R)"
} | gzip -n -9 > "$STAGE_DIR/usr/share/doc/yadorilink/changelog.gz"

# control/postinst/postrm: substitute @VERSION@/@ARCH@ into control,
# copy postinst/postrm as-is (must be executable, LF line endings).
sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCH@/$ARCH/" \
    "$SCRIPT_DIR/debian/control" > "$STAGE_DIR/DEBIAN/control"
install -m 755 "$SCRIPT_DIR/debian/postinst" "$STAGE_DIR/DEBIAN/postinst"
install -m 755 "$SCRIPT_DIR/debian/postrm" "$STAGE_DIR/DEBIAN/postrm"

log "Staged package tree at $STAGE_DIR"

# --- 3. Build the .deb ------------------------------------------------------
mkdir -p "$OUT_DIR"
DEB_PATH="$OUT_DIR/yadorilink_${VERSION}_${ARCH}.deb"

if ! command -v dpkg-deb >/dev/null 2>&1; then
    log "ERROR: dpkg-deb not found. Install it (Debian/Ubuntu: 'apt-get install dpkg-dev'; macOS dev/test only: 'brew install dpkg')."
    exit 1
fi

# --root-owner-group: every file in the payload is owned by root:root in
# the resulting archive regardless of the uid/gid that ran this script --
# required for a real system package (files installed by dpkg/apt always
# run as root anyway), and avoids leaking the build machine's own uid/gid
# into the shipped artifact.
dpkg-deb --build --root-owner-group "$STAGE_DIR" "$DEB_PATH"

log "Built $DEB_PATH"

sha256sum "$DEB_PATH" > "$DEB_PATH.sha256" 2>/dev/null || shasum -a 256 "$DEB_PATH" > "$DEB_PATH.sha256"
log "Wrote checksum sidecar $DEB_PATH.sha256"
