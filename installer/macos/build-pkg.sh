#!/bin/bash
#
# installer/macos/build-pkg.sh
#
# Builds a macOS.pkg installer for yadorilink:
#  - crates/yadorilink-cli -> /usr/local/bin/yadorilink
#  - crates/yadorilink-daemon -> /usr/local/bin/yadorilink-daemon
#  - shell-ext/macos/YadoriLinkFinderSync (the YadoriLink menu bar app,
#  which also carries the FinderSync and File Provider extensions, and links
#  the client core through crates/yadorilink-apple-ffi; the Xcode build runs
#  scripts/generate-swift-bindings.sh to build it)
#  -> /Applications/YadoriLink.app
#
# The server-side yadorilink-coordination binary is deliberately NOT
# included — this is an end-user desktop installer, not a server
# deployment artifact.
#
# SIGNING: release builds must set YADORILINK_RELEASE_BUILD=1 and provide
# YADORILINK_APP_SIGN_IDENTITY (a Developer ID Application identity, used to
# codesign the yadorilink/yadorilink-daemon Mach-O
# binaries directly -- YadoriLink.app is signed separately by
# xcodebuild's own automatic signing) and YADORILINK_PKG_SIGN_IDENTITY (a
# Developer ID Installer identity, used to sign the assembled .pkg). Set
# YADORILINK_NOTARY_PROFILE to an xcrun notarytool keychain profile, OR all
# three of YADORILINK_NOTARY_KEY / _KEY_ID / _ISSUER (an App Store Connect
# API key on disk, which is the form a fresh CI runner can supply -- it has
# no keychain profile to name), to notarize and staple the signed pkg.
# A release build requires one of those two forms: Gatekeeper refuses an
# un-notarized .pkg, so producing one quietly means the failure is found by
# a user instead of by the build. Notarization also rejects a .pkg
# containing any unsigned executable, so YADORILINK_APP_SIGN_IDENTITY is
# not optional once notarization is in play. Local/interim unsigned builds
# are still possible, but this script writes a SHA-256 sidecar next to the
# unsigned artifact so the integrity gap is explicit and checkable.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
XCODE_PROJ_DIR="$REPO_ROOT/shell-ext/macos/YadoriLinkFinderSync"

STAGE_DIR="$SCRIPT_DIR/.stage"
XCODE_BUILD_DIR="$SCRIPT_DIR/.xcode-build"
OUT_DIR="$SCRIPT_DIR/dist"
APP_SIGN_IDENTITY="${YADORILINK_APP_SIGN_IDENTITY:-}"
PKG_SIGN_IDENTITY="${YADORILINK_PKG_SIGN_IDENTITY:-}"
NOTARY_PROFILE="${YADORILINK_NOTARY_PROFILE:-}"
# The other form notarytool accepts: an App Store Connect API key on disk
# plus its key id and issuer. A keychain profile is convenient on a
# developer's own machine and useless on a fresh CI runner, which has no
# keychain profile to name and does have the three pieces of a key.
NOTARY_KEY="${YADORILINK_NOTARY_KEY:-}"
NOTARY_KEY_ID="${YADORILINK_NOTARY_KEY_ID:-}"
NOTARY_ISSUER="${YADORILINK_NOTARY_ISSUER:-}"
RELEASE_BUILD="${YADORILINK_RELEASE_BUILD:-0}"
MANIFEST_KEY_ID="${YADORILINK_RELEASE_MANIFEST_KEY_ID:-}"
MANIFEST_PUBLIC_KEY_HEX="${YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX:-}"

PKG_COMPONENT_ID="com.yadorilink.installer.component"
PKG_VERSION="$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed -E 's/.*"([^"]*)".*/\1/')"

APP_NAME="YadoriLink.app"

log() { echo "== $* =="; }

# --- 0. Sanity checks -------------------------------------------------
command -v cargo >/dev/null || { echo "cargo not found on PATH"; exit 1; }
command -v xcodebuild >/dev/null || { echo "xcodebuild not found (install Xcode)"; exit 1; }
command -v shasum >/dev/null || { echo "shasum not found on PATH"; exit 1; }

# The packaged app must run on the live client over the Rust client core,
# never on the fixture client Debug builds use. Its Release configuration
# picks the live client in ClientFactory.swift; refuse, before the long Rust
# build, if that is no longer so.
CLIENT_FACTORY="$REPO_ROOT/shell-ext/macos/YadoriLinkApp/App/ClientFactory.swift"
if ! awk '/^#else/{release=1} release' "$CLIENT_FACTORY" | grep -q 'makeLiveClient()'; then
    echo "Refusing to package: Release builds of the YadoriLink app must use the live client."
    echo "See $CLIENT_FACTORY."
    exit 1
fi
# The checked-in Swift binding must be what the current Rust code generates
# (the Xcode build regenerates it, so a stale copy would otherwise ship
# unreviewed), and the app's mirror types must still match it.
"$REPO_ROOT/scripts/generate-swift-bindings.sh" --check

if [ "$RELEASE_BUILD" = "1" ] && [ -z "$APP_SIGN_IDENTITY" ]; then
    echo "YADORILINK_RELEASE_BUILD=1 requires YADORILINK_APP_SIGN_IDENTITY."
    echo "Use a Developer ID Application identity to codesign the CLI/daemon binaries."
    exit 1
fi
if [ "$RELEASE_BUILD" = "1" ] && [ -z "$PKG_SIGN_IDENTITY" ]; then
    echo "YADORILINK_RELEASE_BUILD=1 requires YADORILINK_PKG_SIGN_IDENTITY."
    echo "Use a Developer ID Installer identity, then optionally set YADORILINK_NOTARY_PROFILE."
    exit 1
fi
if [ "$RELEASE_BUILD" = "1" ] && { [ -z "$MANIFEST_KEY_ID" ] || [ -z "$MANIFEST_PUBLIC_KEY_HEX" ]; }; then
    echo "YADORILINK_RELEASE_BUILD=1 requires YADORILINK_RELEASE_MANIFEST_KEY_ID and"
    echo "YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX (the offline signing key's public half)."
    exit 1
fi
if [ "$RELEASE_BUILD" = "1" ]; then
    if ! printf '%s' "$MANIFEST_PUBLIC_KEY_HEX" | grep -Eq '^[0-9a-fA-F]{64}$'; then
        echo "YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX must be exactly 64 hexadecimal characters."
        exit 1
    fi
    normalized_manifest_key="$(printf '%s' "$MANIFEST_PUBLIC_KEY_HEX" | tr '[:upper:]' '[:lower:]')"
    if [ "$normalized_manifest_key" = "00e033f866c263139ff4afd165e75bae3cfca67eb32399dddd6e33a3251af1e3" ]; then
        echo "Refusing release build with the known development manifest public key."
        exit 1
    fi
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

if ! security find-identity -v -p codesigning 2>/dev/null | grep -qE "Apple (Development|Distribution)|Developer ID Application"; then
    echo "WARNING: no real 'Apple Development'/'Apple Distribution'/'Developer ID Application'"
    echo "signing identity found in the login keychain. project.yml uses CODE_SIGN_STYLE Automatic +"
    echo "DEVELOPMENT_TEAM 594UQF7QX3; an ad-hoc signature is known NOT to work for this extension"
    echo "(see this script's header comment) so xcodebuild below will likely fail or produce a"
    echo "non-functional .app."
fi

log "Building for yadorilink $PKG_VERSION"

# --- 1. Rust release binaries ------------------------------------------
if [ "$RELEASE_BUILD" = "1" ]; then
    log "cargo build --workspace --release --features yadorilink-daemon/enforce-release-trust-root"
    (
        cd "$REPO_ROOT"
        cargo build --workspace --release \
            --features yadorilink-daemon/enforce-release-trust-root
    )
else
    log "cargo build --workspace --release"
    ( cd "$REPO_ROOT" && cargo build --workspace --release )
fi

YADORILINK_BIN="$REPO_ROOT/target/release/yadorilink"
YADORILINK_DAEMON_BIN="$REPO_ROOT/target/release/yadorilink-daemon"
test -x "$YADORILINK_BIN" || { echo "missing $YADORILINK_BIN"; exit 1; }
test -x "$YADORILINK_DAEMON_BIN" || { echo "missing $YADORILINK_DAEMON_BIN"; exit 1; }

# --- 2. YadoriLink.app (menu bar app + FinderSync + File Provider extensions)
log "xcodegen generate"
( cd "$XCODE_PROJ_DIR" && "$XCODEGEN_BIN" generate )

log "xcodebuild (Release, real signing identity, -allowProvisioningUpdates)"
rm -rf "$XCODE_BUILD_DIR"
( cd "$XCODE_PROJ_DIR" && xcodebuild \
    -project YadoriLinkFinderSync.xcodeproj \
    -scheme YadoriLink \
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
# The eframe status app (yadorilink-status-app) is not shipped on macOS:
# YadoriLink.app is the menu bar app there.
chmod 755 \
    "$STAGE_DIR/usr/local/bin/yadorilink" \
    "$STAGE_DIR/usr/local/bin/yadorilink-daemon"

# Codesign the raw CLI/daemon Mach-O binaries directly -- xcodebuild only
# signs YadoriLink.app above; these two are staged via a plain
# cp and, without this, would ship inside a "signed" .pkg while remaining
# individually unsigned. --options runtime (hardened runtime) + --timestamp
# (secure timestamp) are both required for notarization to accept them.
if [ -n "$APP_SIGN_IDENTITY" ]; then
    log "codesigning CLI/daemon binaries"
    codesign --force --options runtime --timestamp \
        --sign "$APP_SIGN_IDENTITY" \
        "$STAGE_DIR/usr/local/bin/yadorilink" \
        "$STAGE_DIR/usr/local/bin/yadorilink-daemon"
    codesign --verify --strict "$STAGE_DIR/usr/local/bin/yadorilink"
    codesign --verify --strict "$STAGE_DIR/usr/local/bin/yadorilink-daemon"
fi

# ditto (not cp -R) preserves the.app bundle's resource forks / extended
# attributes / code signature exactly, which a plain recursive copy can
# silently corrupt.
ditto "$APP_PATH" "$STAGE_DIR/Applications/$APP_NAME"

# --- 4. Component.pkg (pkgbuild) ---------------------------------------
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

# --- 5. Wrap in a distribution.pkg (productbuild) ----------------------
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
        log "notarytool submit --wait (keychain profile)"
        xcrun notarytool submit "$SIGNED_PKG" --keychain-profile "$NOTARY_PROFILE" --wait
        log "stapler staple"
        xcrun stapler staple "$SIGNED_PKG"
    elif [ -n "$NOTARY_KEY" ] && [ -n "$NOTARY_KEY_ID" ] && [ -n "$NOTARY_ISSUER" ]; then
        command -v xcrun >/dev/null || { echo "xcrun not found on PATH"; exit 1; }
        log "notarytool submit --wait (App Store Connect API key)"
        xcrun notarytool submit "$SIGNED_PKG" \
            --key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" --wait
        log "stapler staple"
        xcrun stapler staple "$SIGNED_PKG"
    else
        # Partial credentials are treated as a mistake, not as "no
        # notarization requested". Supplying two of the three pieces of an
        # API key and getting a cheerful "was not notarized" is how an
        # un-notarized artifact reaches the verification below and fails
        # there instead, with a message about Gatekeeper that says nothing
        # about the actual cause.
        if [ -n "$NOTARY_KEY$NOTARY_KEY_ID$NOTARY_ISSUER" ]; then
            echo "Notarization credentials are incomplete: the API-key form needs all three of"
            echo "YADORILINK_NOTARY_KEY, YADORILINK_NOTARY_KEY_ID and YADORILINK_NOTARY_ISSUER."
            echo "Set all three, or set YADORILINK_NOTARY_PROFILE instead."
            exit 1
        fi
        # A release build must not quietly produce an un-notarized artifact.
        # Gatekeeper refuses one on any current macOS, so this would be
        # discovered by a user rather than by the build.
        if [ "$RELEASE_BUILD" = "1" ]; then
            echo "YADORILINK_RELEASE_BUILD=1 requires notarization: set YADORILINK_NOTARY_PROFILE,"
            echo "or all three of YADORILINK_NOTARY_KEY / _KEY_ID / _ISSUER."
            exit 1
        fi
        echo "No notarization credentials set; signed pkg was not notarized."
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
