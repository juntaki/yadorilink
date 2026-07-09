#!/bin/bash
#
# installer/macos/verify-pkg.sh
#
# Standalone verification for a built (or downloaded) yadorilink .pkg —
# part of add-release-artifact-verification, tasks.md 2.1. Unlike the
# signing/verification steps already inline in build-pkg.sh (which only
# run right after that same script produces the artifact), this can be
# pointed at any .pkg — e.g. one downloaded from a release page, or
# handed off from a build machine — to independently confirm its checksum
# and platform signature/notarization before anyone runs it.
#
# Checks performed:
#   1. SHA-256 checksum against the artifact's `<name>.sha256` sidecar
#      (release-blocking: every artifact must have a published checksum).
#   2. `pkgutil --check-signature` — reports signed/unsigned status.
#   3. `spctl -a -vvv -t install` — Gatekeeper's install-time verdict.
#   4. `xcrun stapler validate` — whether a notarization ticket is stapled.
#
# By default this only *reports* signature/notarization status without
# failing on unsigned (matching this project's documented allowance for
# local/interim unsigned builds — see installer/macos/README.md's
# "Signing and notarization" section). Pass
# --release to additionally require signed + notarized + stapled, per
# the release rule that shipped packages must be signed, notarized,
# stapled, and checksummed.
#
# Usage:
#   installer/macos/verify-pkg.sh path/to/yadorilink-<version>.pkg
#   installer/macos/verify-pkg.sh --release path/to/yadorilink-<version>.pkg

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

# --- 5. Payload contents (add-desktop-status-app task 4.4) ---------------
# Confirms the status app binary is actually present in the built payload
# — a real, if narrow, smoke test that doesn't require installing the pkg
# or a running window manager: `pkgutil --expand-full` recursively expands
# the outer distribution pkg's nested component pkg(s) and unpacks each
# `Payload` to plain files, so this is checking the exact bytes that would
# land on disk at `/usr/local/bin/yadorilink-status-app`.
log "payload contents (yadorilink-status-app)"
EXPAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/verify-pkg-expand.XXXXXX")"
trap 'rm -rf "$EXPAND_DIR"' EXIT
if pkgutil --expand-full "$PKG" "$EXPAND_DIR/expanded" >/tmp/verify-pkg-expand.$$ 2>&1; then
    if find "$EXPAND_DIR/expanded" -type f -name "yadorilink-status-app" | grep -q .; then
        ok "payload includes usr/local/bin/yadorilink-status-app"
    else
        fail "payload does not include yadorilink-status-app"
    fi
else
    fail "pkgutil --expand-full failed"
    cat /tmp/verify-pkg-expand.$$ >&2
fi
rm -f /tmp/verify-pkg-expand.$$

echo
if [ "$FAILURES" -gt 0 ]; then
    echo "verify-pkg.sh: $FAILURES check(s) failed for $PKG" >&2
    exit 1
fi
echo "verify-pkg.sh: all required checks passed for $PKG"
exit 0
