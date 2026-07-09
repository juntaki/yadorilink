#!/bin/bash
#
# installer/macos/build-pkg.sh
#
# Builds a macOS .pkg installer for yadorilink:
#   - crates/yadorilink-cli          -> /usr/local/bin/yadorilink
#   - crates/yadorilink-daemon       -> /usr/local/bin/yadorilink-daemon
#   - crates/yadorilink-desktop-app  -> /usr/local/bin/yadorilink-status-app
#     (the menu-bar status app. Shipped as a plain
#     signed executable, not an .app bundle — see this script's
#     staging comment below for why.)
#   - shell-ext/macos/YadoriLinkFinderSync (host app + both extensions)
#                                -> /Applications/YadoriLinkFinderSyncHost.app
#
# Server-side relay and coordination-service deployment components are
# deliberately NOT included — this is an end-user desktop installer, not
# a server deployment artifact.
#
# SIGNING: release builds must set YADORILINK_RELEASE_BUILD=1 and provide
# YADORILINK_PKG_SIGN_IDENTITY (a Developer ID Installer identity). Set
# YADORILINK_NOTARY_PROFILE to an xcrun notarytool keychain profile to
# notarize and staple the signed pkg. Local/interim unsigned builds are
# still possible, but this script writes a SHA-256 sidecar next to the
# unsigned artifact so the integrity gap is explicit and checkable.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
XCODE_PROJ_DIR="$REPO_ROOT/shell-ext/macos/YadoriLinkFinderSync"

STAGE_DIR="$SCRIPT_DIR/.stage"
XCODE_BUILD_DIR="$SCRIPT_DIR/.xcode-build"
OUT_DIR="$SCRIPT_DIR/dist"
PKG_SIGN_IDENTITY="${YADORILINK_PKG_SIGN_IDENTITY:-}"
NOTARY_PROFILE="${YADORILINK_NOTARY_PROFILE:-}"
RELEASE_BUILD="${YADORILINK_RELEASE_BUILD:-0}"

PKG_COMPONENT_ID="com.yadorilink.installer.component"
PKG_VERSION="$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed -E 's/.*"([^"]*)".*/\1/')"

APP_NAME="YadoriLinkFinderSyncHost.app"

log() { echo "== $* =="; }

# --- 0. Sanity checks -------------------------------------------------
command -v cargo >/dev/null || { echo "cargo not found on PATH"; exit 1; }
command -v xcodebuild >/dev/null || { echo "xcodebuild not found (install Xcode)"; exit 1; }
command -v shasum >/dev/null || { echo "shasum not found on PATH"; exit 1; }

if [ "$RELEASE_BUILD" = "1" ] && [ -z "$PKG_SIGN_IDENTITY" ]; then
    echo "YADORILINK_RELEASE_BUILD=1 requires YADORILINK_PKG_SIGN_IDENTITY."
    echo "Use a Developer ID Installer identity, then optionally set YADORILINK_NOTARY_PROFILE."
    exit 1
fi

XCODEGEN_BIN="$(command -v xcodegen || true)"
if [ -z "$XCODEGEN_BIN" ] && [ -x "$HOME/xcodegen-bin/xcodegen" ]; then
    XCODEGEN_BIN="$HOME/xcodegen-bin/xcodegen"
fi
if [ -z "$XCODEGEN_BIN" ]; then
    echo "xcodegen not found on PATH or in ~/xcodegen-bin/. Install it (e.g. 'brew install xcodegen')"
    echo "or fetch the release binary — see shell-ext/macos/YadoriLinkFinderSync/project.yml."
    exit 1
fi

if ! security find-identity -v -p codesigning 2>/dev/null | grep -qE "Apple (Development|Distribution)"; then
    echo "WARNING: no real 'Apple Development'/'Apple Distribution' signing identity found in the"
    echo "login keychain. project.yml uses CODE_SIGN_STYLE Automatic + DEVELOPMENT_TEAM 594UQF7QX3;"
    echo "an ad-hoc signature is known NOT to work for this extension (see this script's header"
    echo "comment) so xcodebuild below will likely fail or produce a non-functional .app."
fi

log "Building for yadorilink $PKG_VERSION"

# --- 1. Rust release binaries ------------------------------------------
log "cargo build --workspace --release"
( cd "$REPO_ROOT" && cargo build --workspace --release )

YADORILINK_BIN="$REPO_ROOT/target/release/yadorilink"
YADORILINK_DAEMON_BIN="$REPO_ROOT/target/release/yadorilink-daemon"
YADORILINK_STATUS_APP_BIN="$REPO_ROOT/target/release/yadorilink-status-app"
test -x "$YADORILINK_BIN" || { echo "missing $YADORILINK_BIN"; exit 1; }
test -x "$YADORILINK_DAEMON_BIN" || { echo "missing $YADORILINK_DAEMON_BIN"; exit 1; }
test -x "$YADORILINK_STATUS_APP_BIN" || { echo "missing $YADORILINK_STATUS_APP_BIN"; exit 1; }

# --- 2. .app bundle (host app + FinderSync + File Provider extensions) -
log "xcodegen generate"
( cd "$XCODE_PROJ_DIR" && "$XCODEGEN_BIN" generate )

log "xcodebuild (Release, real signing identity, -allowProvisioningUpdates)"
rm -rf "$XCODE_BUILD_DIR"
( cd "$XCODE_PROJ_DIR" && xcodebuild \
    -project YadoriLinkFinderSync.xcodeproj \
    -scheme YadoriLinkFinderSyncHost \
    -configuration Release \
    -derivedDataPath "$XCODE_BUILD_DIR" \
    -allowProvisioningUpdates \
    build )

APP_PATH="$XCODE_BUILD_DIR/Build/Products/Release/$APP_NAME"
test -d "$APP_PATH" || { echo "missing $APP_PATH"; exit 1; }

log "verifying .app signature"
codesign --verify --deep --strict "$APP_PATH"
codesign -dvvv "$APP_PATH" 2>&1 | grep -E "Authority|TeamIdentifier" | head -3

# --- 3. Stage the install root ------------------------------------------
log "staging install root"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/usr/local/bin" "$STAGE_DIR/Applications"

cp "$YADORILINK_BIN" "$STAGE_DIR/usr/local/bin/yadorilink"
cp "$YADORILINK_DAEMON_BIN" "$STAGE_DIR/usr/local/bin/yadorilink-daemon"
# Staged as a plain binary next to
# `yadorilink`/`yadorilink-daemon`, not wrapped in an `.app` bundle —
# `tray-icon`'s `NSStatusItem` works fine from a bare executable given a
# running `NSApplication`/event loop (this app's `main.rs`), and a real
# multi-resolution `.icns` + `Info.plist`-bundled `.app` (needed for it to
# show in Launchpad/the Applications list) is packaging work intentionally
# deferred for now.
cp "$YADORILINK_STATUS_APP_BIN" "$STAGE_DIR/usr/local/bin/yadorilink-status-app"
chmod 755 \
    "$STAGE_DIR/usr/local/bin/yadorilink" \
    "$STAGE_DIR/usr/local/bin/yadorilink-daemon" \
    "$STAGE_DIR/usr/local/bin/yadorilink-status-app"

# ditto (not cp -R) preserves the .app bundle's resource forks / extended
# attributes / code signature exactly, which a plain recursive copy can
# silently corrupt.
ditto "$APP_PATH" "$STAGE_DIR/Applications/$APP_NAME"

# --- 4. Component .pkg (pkgbuild) ---------------------------------------
mkdir -p "$OUT_DIR"
COMPONENT_PKG="$OUT_DIR/YadoriLinkComponent.pkg"
COMPONENT_PLIST="$SCRIPT_DIR/.component.plist"

pkgbuild --analyze --root "$STAGE_DIR" "$COMPONENT_PLIST"
# Force the app to install exactly at /Applications, not wherever
# Launch Services thinks a same-bundle-id app currently lives — this is
# a fresh, fixed-location install, not a relocatable one.
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$COMPONENT_PLIST" 2>/dev/null || true

log "pkgbuild -> $COMPONENT_PKG"
pkgbuild \
    --root "$STAGE_DIR" \
    --identifier "$PKG_COMPONENT_ID" \
    --version "$PKG_VERSION" \
    --install-location / \
    --scripts "$SCRIPT_DIR/scripts" \
    --component-plist "$COMPONENT_PLIST" \
    "$COMPONENT_PKG"

# --- 5. Wrap in a distribution .pkg (productbuild) ----------------------
DIST_XML="$SCRIPT_DIR/.Distribution.generated.xml"
sed "s/__VERSION__/$PKG_VERSION/" "$SCRIPT_DIR/Distribution.xml" > "$DIST_XML"

UNSIGNED_PKG="$OUT_DIR/yadorilink-$PKG_VERSION-unsigned.pkg"
log "productbuild -> $UNSIGNED_PKG"
productbuild \
    --distribution "$DIST_XML" \
    --package-path "$OUT_DIR" \
    "$UNSIGNED_PKG"

rm -f "$DIST_XML" "$COMPONENT_PLIST"

if [ -n "$PKG_SIGN_IDENTITY" ]; then
    command -v productsign >/dev/null || { echo "productsign not found on PATH"; exit 1; }
    SIGNED_PKG="$OUT_DIR/yadorilink-$PKG_VERSION.pkg"
    log "productsign -> $SIGNED_PKG"
    productsign --sign "$PKG_SIGN_IDENTITY" "$UNSIGNED_PKG" "$SIGNED_PKG"

    if [ -n "$NOTARY_PROFILE" ]; then
        command -v xcrun >/dev/null || { echo "xcrun not found on PATH"; exit 1; }
        log "notarytool submit --wait"
        xcrun notarytool submit "$SIGNED_PKG" --keychain-profile "$NOTARY_PROFILE" --wait
        log "stapler staple"
        xcrun stapler staple "$SIGNED_PKG"
    else
        echo "YADORILINK_NOTARY_PROFILE not set; signed pkg was not notarized."
    fi

    log "verifying signed pkg"
    pkgutil --check-signature "$SIGNED_PKG"
    spctl -a -vvv -t install "$SIGNED_PKG"
    shasum -a 256 "$SIGNED_PKG" > "$SIGNED_PKG.sha256"
    log "Done: $SIGNED_PKG"
else
    shasum -a 256 "$UNSIGNED_PKG" > "$UNSIGNED_PKG.sha256"
    log "Done: $UNSIGNED_PKG"
    echo "This .pkg is UNSIGNED/unnotarized — publish and verify $UNSIGNED_PKG.sha256 with it."
fi
