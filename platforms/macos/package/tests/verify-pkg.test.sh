#!/bin/bash
# Tests of verify-pkg.sh payload checks on synthetic unsigned packages: a payload
# with every shipped file passes (non-release mode), and a payload missing the
# CLI, the daemon or the uninstaller fails. macOS only (pkgbuild, pkgutil).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="$HERE/../verify-pkg.sh"
[ "$(uname -s)" = "Darwin" ] || { echo "verify-pkg tests skipped (not macOS)"; exit 0; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/verify-pkg-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
fail() { echo "FAIL: $*" >&2; FAILS=$((FAILS + 1)); }

# build_pkg NAME [file-to-omit]: a payload shaped like build-pkg.sh's staging root.
build_pkg() {
    local name="$1" omit="${2:-}" root="$WORK/$1-root"
    mkdir -p "$root/Applications/YadoriLink.app/Contents" "$root/usr/local/bin" "$root/usr/local/share/yadorilink"
    echo x > "$root/usr/local/bin/yadorilink"
    echo x > "$root/usr/local/bin/yadorilink-daemon"
    echo x > "$root/usr/local/share/yadorilink/uninstall.sh"
    [ -z "$omit" ] || rm -f "$root/$omit"
    pkgbuild --root "$root" --identifier test.component --version 0 "$WORK/$name-c.pkg" >/dev/null 2>&1 || { fail "pkgbuild $name"; return 1; }
    productbuild --package "$WORK/$name-c.pkg" "$WORK/$name-unsigned.pkg" >/dev/null 2>&1 || { fail "productbuild $name"; return 1; }
    (cd "$WORK" && shasum -a 256 "$name-unsigned.pkg" > "$name-unsigned.pkg.sha256")
}

build_pkg complete && {
    "$VERIFY" "$WORK/complete-unsigned.pkg" >"$WORK/complete.out" 2>&1 || { fail "complete payload should pass"; cat "$WORK/complete.out" >&2; }
}
for omit in usr/local/bin/yadorilink usr/local/bin/yadorilink-daemon usr/local/share/yadorilink/uninstall.sh; do
    n="missing-$(basename "$omit")"
    build_pkg "$n" "$omit" || continue
    if "$VERIFY" "$WORK/$n-unsigned.pkg" >"$WORK/$n.out" 2>&1; then
        fail "payload without $omit should fail"
    else
        grep -q "payload does not include $omit" "$WORK/$n.out" || fail "failure for $omit should name it"
    fi
done

[ "$FAILS" -eq 0 ] || { echo "$FAILS failure(s)" >&2; exit 1; }
echo "verify-pkg payload tests passed"
