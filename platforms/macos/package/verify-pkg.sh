#!/bin/bash
#
# platforms/macos/package/verify-pkg.sh
#
# Standalone verification for a built (or downloaded) yadorilink.pkg.
# Unlike the signing/verification steps already inline in build-pkg.sh (which only
# run right after that same script produces the artifact), this can be
# pointed at any.pkg — e.g. one downloaded from a release page, or
# handed off from a build machine — to independently confirm its checksum
# and platform signature/notarization before anyone runs it.
#
# Checks performed:
#  1. SHA-256 checksum against the artifact's `<name>.sha256` sidecar
#  (release-blocking: every artifact must have a published checksum).
#  2. `pkgutil --check-signature` — reports signed/unsigned status.
#  3. `spctl -a -vvv -t install` — Gatekeeper's install-time verdict.
#  4. `xcrun stapler validate` — whether a notarization ticket is stapled.
#  5. Payload contents (YadoriLink.app, the CLI, the daemon and uninstall.sh
#  present, no eframe status app). A missing file fails in every mode.
#  6. --release only: signatures of what ships. For the app, both
#     extensions and every nested Mach-O (incl. usr/local/bin/*):
#     `codesign --verify --strict --deep`, Authority = Developer ID
#     Application, hardened runtime, secure timestamp, one common Team ID,
#     no get-task-allow; app and extension entitlements must match the
#     entitlement files in this repo; the pkg must be Developer ID Installer
#     signed; Gatekeeper must accept the app.
#
# By default this only *reports* signature/notarization status without
# failing on unsigned (matching this project's documented allowance for
# local/interim unsigned builds — see platforms/macos/package/README.md's
# "Signing and notarization" section). Pass
# --release to additionally require signed + notarized + stapled, per
# the release rule that shipped packages must be signed, notarized,
# stapled, and checksummed.
#
# Usage:
#  platforms/macos/package/verify-pkg.sh path/to/yadorilink-<version>.pkg
#  platforms/macos/package/verify-pkg.sh --release path/to/yadorilink-<version>.pkg

set -uo pipefail

RELEASE_MODE=0
if [ "${1:-}" = "--release" ]; then
    RELEASE_MODE=1
    shift
fi

PKG="${1:-}"
if [ -z "$PKG" ] || [ ! -f "$PKG" ]; then
    echo "usage: $0 [--release] <path-to.pkg>" >&2
    exit 2
fi

FAILURES=0
fail() { echo "FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
ok() { echo "OK: $*"; }

log() { echo "== $* =="; }

# --- 1. Checksum -------------------------------------------------------
log "checksum"
SIDECAR="$PKG.sha256"
if [ -f "$SIDECAR" ]; then
    if (cd "$(dirname "$PKG")" && shasum -a 256 -c "$(basename "$SIDECAR")") >/tmp/verify-pkg-checksum.$$ 2>&1; then
        ok "checksum matches $SIDECAR"
    else
        fail "checksum mismatch against $SIDECAR"
        cat /tmp/verify-pkg-checksum.$$ >&2
    fi
    rm -f /tmp/verify-pkg-checksum.$$
else
    fail "no checksum sidecar found at $SIDECAR"
fi

# --- 2. pkgutil signature check ----------------------------------------
log "pkgutil --check-signature"
PKGUTIL_OUT="$(pkgutil --check-signature "$PKG" 2>&1)"
echo "$PKGUTIL_OUT"
# Match only the actual "Status:" line, not the whole output — the
# artifact's own filename (e.g. "yadorilink-0.1.0-unsigned.pkg", echoed
# by pkgutil right above the Status line) contains "signed" as a
# substring of "unsigned", so a plain `grep "signed"` over $PKGUTIL_OUT
# would false-positive on an unsigned package. Anchor on the Status line
# and check for "no signature" specifically instead.
STATUS_LINE="$(echo "$PKGUTIL_OUT" | grep "Status:" || true)"
if echo "$STATUS_LINE" | grep -q "no signature"; then
    SIGNED=0
    if [ "$RELEASE_MODE" -eq 1 ]; then
        fail "pkg is not signed (--release requires a signed pkg)"
    else
        echo "NOTE: pkg is unsigned — expected for local/interim builds; use --release to enforce signing"
    fi
elif [ -n "$STATUS_LINE" ]; then
    SIGNED=1
    ok "pkg is signed ($STATUS_LINE)"
else
    SIGNED=0
    fail "could not determine signature status from pkgutil output"
fi

# --- 3. Gatekeeper install verdict --------------------------------------
log "spctl -a -vvv -t install"
SPCTL_OUT="$(spctl -a -vvv -t install "$PKG" 2>&1)"
echo "$SPCTL_OUT"
if echo "$SPCTL_OUT" | grep -q "accepted"; then
    ok "spctl accepted the package for install"
elif [ "$RELEASE_MODE" -eq 1 ]; then
    fail "spctl did not accept the package for install"
else
    echo "NOTE: spctl rejected an unsigned package — expected; use --release to enforce"
fi

# --- 4. Notarization staple ----------------------------------------------
log "xcrun stapler validate"
if command -v xcrun >/dev/null 2>&1; then
    STAPLE_OUT="$(xcrun stapler validate "$PKG" 2>&1)"
    echo "$STAPLE_OUT"
    if echo "$STAPLE_OUT" | grep -qi "worked"; then
        ok "notarization ticket is stapled"
    elif [ "$RELEASE_MODE" -eq 1 ]; then
        fail "no valid stapled notarization ticket (--release requires notarization)"
    else
        echo "NOTE: no stapled ticket — expected for unsigned/un-notarized local builds"
    fi
else
    echo "NOTE: xcrun not found; skipping stapler check"
fi

# --- 5. Payload contents --------------------------------------------------
# Confirms the payload carries the YadoriLink menu bar app and no longer
# carries the eframe status app — a narrow smoke test that doesn't require
# installing the pkg: `pkgutil --expand-full` recursively expands the outer
# distribution pkg's nested component pkg(s) and unpacks each `Payload` to
# plain files, so this checks what would land on disk.
log "payload contents (YadoriLink.app, no yadorilink-status-app)"
EXPAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/verify-pkg-expand.XXXXXX")"
trap 'rm -rf "$EXPAND_DIR"' EXIT
if pkgutil --expand-full "$PKG" "$EXPAND_DIR/expanded" >/tmp/verify-pkg-expand.$$ 2>&1; then
    if find "$EXPAND_DIR/expanded" -type d -path "*/Applications/YadoriLink.app" | grep -q .; then
        ok "payload includes Applications/YadoriLink.app"
    else
        fail "payload does not include Applications/YadoriLink.app"
    fi
    for shipped in usr/local/bin/yadorilink usr/local/bin/yadorilink-daemon usr/local/share/yadorilink/uninstall.sh; do
        if find "$EXPAND_DIR/expanded" -type f -path "*/$shipped" | grep -q .; then
            ok "payload includes $shipped"
        else
            fail "payload does not include $shipped"
        fi
    done
    if find "$EXPAND_DIR/expanded" -name "yadorilink-status-app" | grep -q .; then
        fail "payload still includes yadorilink-status-app"
    else
        ok "payload does not include yadorilink-status-app"
    fi
else
    fail "pkgutil --expand-full failed"
    cat /tmp/verify-pkg-expand.$$ >&2
fi
rm -f /tmp/verify-pkg-expand.$$

# --- 6. Payload signatures (release only) ---------------------------------
# Expected entitlements live in the repo; the host app and the extensions must
# carry exactly those security entitlements (Developer ID signing may add
# identifier keys).
APP_DIR="$(dirname "$0")/../app"
expected_ent_for() {
    case "$1" in
        */YadoriLink.app) echo "$APP_DIR/YadoriLinkApp/App/App.entitlements" ;;
        *YadoriLinkFinderSync.appex) echo "$APP_DIR/YadoriLinkFinderSync/Extension/Extension.entitlements" ;;
        *YadoriLinkFileProvider.appex) echo "$APP_DIR/YadoriLinkFileProvider/Extension/Extension.entitlements" ;;
    esac
}
# plist keys at top level, one per line
plist_keys() { plutil -p "$1" | sed -n 's/^  "\(.*\)" => .*/\1/p'; }
plist_value() { # file key -> normalized value
    plutil -extract "$(echo "$2" | sed 's/\./\\./g')" xml1 -o - "$1" 2>/dev/null
}

TEAM_IDS=""
check_item() { # path
    local item="$1" rel="${1#$EXPAND_DIR/expanded/}" info ent expected k
    if ! codesign --verify --strict --deep "$item" >/dev/null 2>&1; then
        fail "$rel: codesign --verify --strict --deep failed"
        return
    fi
    info="$(codesign -dvvv "$item" 2>&1)"
    echo "$info" | grep -q '^Authority=Developer ID Application' || fail "$rel: Authority is not Developer ID Application"
    echo "$info" | grep -Eq 'flags=0x[0-9a-f]+\(.*runtime' || fail "$rel: hardened runtime flag missing"
    echo "$info" | grep -q '^Timestamp=' || fail "$rel: no secure timestamp"
    TEAM_IDS="$TEAM_IDS$(echo "$info" | sed -n 's/^TeamIdentifier=//p')
"
    ent="$(mktemp "${TMPDIR:-/tmp}/verify-pkg-ent.XXXXXX")"
    codesign -d --entitlements :- "$item" >"$ent" 2>/dev/null
    if [ -s "$ent" ] && plist_keys "$ent" | grep -qx 'com.apple.security.get-task-allow'; then
        fail "$rel: has get-task-allow (debug build)"
    fi
    expected="$(expected_ent_for "$item")"
    if [ -n "$expected" ]; then
        if [ -z "$(plist_keys "$expected" 2>/dev/null)" ]; then
            fail "$rel: expected entitlements file missing or unreadable: $expected"
        elif [ ! -s "$ent" ]; then
            fail "$rel: no entitlements embedded"
        else
            for k in $(plist_keys "$expected"); do
                [ "$(plist_value "$expected" "$k")" = "$(plist_value "$ent" "$k")" ] || fail "$rel: entitlement $k differs from $expected"
            done
            for k in $(plist_keys "$ent" | grep '^com\.apple\.security\.'); do
                plist_keys "$expected" | grep -qx "$k" || fail "$rel: unexpected entitlement $k"
            done
        fi
    fi
    rm -f "$ent"
    echo "checked $rel"
}

if [ "$RELEASE_MODE" -eq 1 ]; then
    log "payload signatures and entitlements (--release)"
    ROOT="$EXPAND_DIR/expanded"
    APP="$(find "$ROOT" -type d -path "*/Applications/YadoriLink.app" | head -1)"
    if [ -z "$APP" ]; then
        fail "cannot check payload signatures: YadoriLink.app not found"
    else
        for appex in YadoriLinkFinderSync YadoriLinkFileProvider; do
            [ -d "$APP/Contents/PlugIns/$appex.appex" ] || fail "missing PlugIns/$appex.appex"
        done
        check_item "$APP"
        # All three signed bundles embed a Developer ID profile for their own
        # bundle id that authorizes the App Group each signs.
        python3 "$(dirname "$0")/validate-macos-profiles.py" built-app "$APP" >&2 \
            || fail "embedded provisioning profiles of YadoriLink.app and its extensions are invalid"
        for appex in "$APP"/Contents/PlugIns/*.appex; do [ -d "$appex" ] && check_item "$appex"; done
        # Every other Mach-O: nested frameworks/dylibs/helpers and the CLI.
        while IFS= read -r f; do
            file "$f" | grep -q 'Mach-O' && check_item "$f"
        done < <(find "$APP" "$ROOT" -path "*/usr/local/bin/*" -type f -print -o -path "$APP/*" -type f -print | sort -u)
        if [ "$(echo "$TEAM_IDS" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')" -gt 1 ]; then
            fail "payload items have different Team IDs: $(echo "$TEAM_IDS" | sort -u | tr '\n' ' ')"
        fi
        if spctl -a -t exec -vv "$APP" 2>&1 | grep -q accepted; then
            ok "spctl accepted YadoriLink.app"
        else
            fail "spctl did not accept YadoriLink.app"
        fi
    fi
    echo "$PKGUTIL_OUT" | grep -q "Developer ID Installer" || fail "pkg is not signed by a Developer ID Installer certificate"
fi

echo
if [ "$FAILURES" -gt 0 ]; then
    echo "verify-pkg.sh: $FAILURES check(s) failed for $PKG" >&2
    exit 1
fi
echo "verify-pkg.sh: all required checks passed for $PKG"
exit 0
