#!/bin/bash
# build-yadorilink-mvp tasks 10.1/10.5: builds the Rust FFI core, the
# FinderSync extension, and the host app, then assembles and ad-hoc signs
# the app bundle — entirely from the command line, without an .xcodeproj.
#
# WHY NO XCODE PROJECT (documented deviation from the task brief's
# suggested `xcodebuild -project ... -scheme ... build`): this repo's
# only real macOS build machine (m1mac, see the task brief) has Xcode's
# command-line tools but neither Homebrew nor `xcodegen` available, and
# hand-authoring a modern Xcode `project.pbxproj` (plist-ish but with a
# fragile, version-sensitive object graph) by hand, with no way to open
# it in Xcode's GUI to sanity-check it, is a much higher-risk path than
# driving `swiftc`/`codesign` directly — both of which are stable,
# documented, scriptable CLI surfaces. `swiftc -import-objc-header` gives
# the same bridging-header mechanism Xcode's build system would use, and
# a FinderSync `.appex` is, underneath Xcode's tooling, just a bundle
# with a specific Info.plist shape (NSExtensionPointIdentifier =
# com.apple.FinderSync) embedded under a host `.app`'s Contents/PlugIns —
# nothing here strictly requires Xcode's project system, only its
# toolchain (swiftc/clang/codesign from Xcode-26.5.0.app), which this
# script does use. If `xcodegen` becomes available later, regenerating a
# real .xcodeproj from a small project.yml pointing at these same source
# files would be a reasonable follow-up for anyone who wants to iterate
# in Xcode's GUI/debugger.
#
# Usage (on a real macOS machine with Xcode installed, e.g. m1mac):
#   DEVELOPER_DIR=/Applications/Xcode-26.5.0.app/Contents/Developer ./build.sh
#
# Produces:
#   build/YadoriLinkFinderSyncHost.app  (host app with the extension embedded
#                                      under Contents/PlugIns/, ad-hoc signed)

set -euo pipefail

: "${DEVELOPER_DIR:=/Applications/Xcode-26.5.0.app/Contents/Developer}"
export DEVELOPER_DIR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"
CORE_DIR="$ROOT_DIR/../core"
EXT_DIR="$ROOT_DIR/Extension"
HOST_DIR="$ROOT_DIR/HostApp"
BUILD_DIR="$ROOT_DIR/build"

RUST_TARGET="aarch64-apple-darwin"
SWIFT_TARGET="arm64-apple-macos11"

HOST_APP_ID="com.juntaki.yadorilink"
HOST_APP_NAME="YadoriLinkFinderSyncHost"
EXT_ID="com.juntaki.yadorilink.FinderSync"
EXT_NAME="YadoriLinkFinderSync"

echo "== yadorilink macOS shell extension build =="
echo "DEVELOPER_DIR=$DEVELOPER_DIR"
xcrun swift --version
rustc --version

SDK="$(xcrun --sdk macosx --show-sdk-path)"
echo "SDK: $SDK"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# --- 1. Rust FFI core (task 10.1) -------------------------------------
echo "-- building yadorilink-shell-ext-macos-core (release, $RUST_TARGET) --"
( cd "$CORE_DIR" && cargo build --release --target "$RUST_TARGET" )
CORE_LIB_DIR="$CORE_DIR/target/$RUST_TARGET/release"
CORE_LIB="$CORE_LIB_DIR/libyadorilink_shell_core.a"
test -f "$CORE_LIB" || { echo "missing $CORE_LIB"; exit 1; }

# The Rust staticlib pulls in tokio/prost/tonic transitively (via
# yadorilink-ipc-proto — see core/Cargo.toml's doc comment); discover the
# exact system libraries/frameworks it needs at final-link time rather
# than hardcoding a guessed list, so this keeps working if that
# dependency tree changes.
echo "-- discovering native-static-libs for the final swiftc link step --"
NATIVE_LIBS="$(cd "$CORE_DIR" && cargo rustc --release --target "$RUST_TARGET" --crate-type staticlib -- --print native-static-libs 2>&1 | grep 'native-static-libs:' | sed -E 's/.*native-static-libs: *//')"
echo "native-static-libs: $NATIVE_LIBS"

# --- 2. FinderSync extension binary (tasks 10.1-10.3) -----------------
echo "-- compiling FinderSync extension --"
APPEX_BUNDLE="$BUILD_DIR/$EXT_NAME.appex"
mkdir -p "$APPEX_BUNDLE/Contents/MacOS"
mkdir -p "$APPEX_BUNDLE/Contents/Resources"

# shellcheck disable=SC2086
xcrun swiftc \
    -sdk "$SDK" \
    -target "$SWIFT_TARGET" \
    -import-objc-header "$EXT_DIR/YadoriLinkFinderSync-Bridging-Header.h" \
    -I "$CORE_DIR/include" \
    -L "$CORE_LIB_DIR" \
    -lyadorilink_shell_core \
    -framework Cocoa \
    -framework FinderSync \
    $NATIVE_LIBS \
    -o "$APPEX_BUNDLE/Contents/MacOS/$EXT_NAME" \
    "$EXT_DIR/FinderSync.swift"

cp "$EXT_DIR/Info.plist" "$APPEX_BUNDLE/Contents/Info.plist"

# --- 3. Host app binary (task 10.5) ------------------------------------
echo "-- compiling host app --"
APP_BUNDLE="$BUILD_DIR/$HOST_APP_NAME.app"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"
mkdir -p "$APP_BUNDLE/Contents/PlugIns"

xcrun swiftc \
    -sdk "$SDK" \
    -target "$SWIFT_TARGET" \
    -framework Cocoa \
    -o "$APP_BUNDLE/Contents/MacOS/$HOST_APP_NAME" \
    "$HOST_DIR/main.swift"

cp "$HOST_DIR/Info.plist" "$APP_BUNDLE/Contents/Info.plist"

# --- 4. Assemble: embed the extension in the host app (task 10.5) -----
echo "-- embedding extension in host app bundle --"
rm -rf "$APP_BUNDLE/Contents/PlugIns/$EXT_NAME.appex"
cp -R "$APPEX_BUNDLE" "$APP_BUNDLE/Contents/PlugIns/$EXT_NAME.appex"

# --- 5. Ad-hoc codesign (task 10.4/10.5) -------------------------------
# No real Apple Developer ID / provisioning profile is available in this
# environment, so both bundles are ad-hoc signed (`--sign -`) for local
# development/testing only. Real distribution would additionally need:
#   - A Developer ID Application certificate (or Mac App Store
#     distribution certificate + provisioning profile).
#   - Hardened Runtime (`--options runtime`) enabled on both bundles,
#     which this ad-hoc build deliberately skips (hardened runtime +
#     ad-hoc signing without a `com.apple.security.get-task-allow`
#     entitlement complicates local debugging for no benefit here).
#   - `xcrun notarytool submit` notarization of the signed, zipped app,
#     then `xcrun stapler staple` — requires an Apple Developer account
#     and network access to Apple's notary service, neither available in
#     this session. Tracked as a follow-up per task 10.5, not blocking.
#   - Proper (non-ad-hoc) entitlements per
#     Extension.sandboxed-reference.entitlements's documented options, if
#     shipping with App Sandbox enabled.
echo "-- ad-hoc signing extension --"
codesign --force --sign - \
    --entitlements "$EXT_DIR/Extension.entitlements" \
    "$APP_BUNDLE/Contents/PlugIns/$EXT_NAME.appex"

echo "-- ad-hoc signing host app --"
codesign --force --sign - "$APP_BUNDLE"

echo "-- verifying signatures --"
codesign -dv --verbose=4 "$APP_BUNDLE/Contents/PlugIns/$EXT_NAME.appex" 2>&1
codesign -dv --verbose=4 "$APP_BUNDLE" 2>&1
codesign --verify --deep --strict "$APP_BUNDLE" && echo "codesign --verify: OK"

echo "== build complete: $APP_BUNDLE =="
