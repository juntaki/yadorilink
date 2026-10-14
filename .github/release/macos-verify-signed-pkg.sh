#!/bin/bash
#
# .github/release/macos-verify-signed-pkg.sh
#
# After build-pkg.sh has built, signed, notarized and stapled the macOS .pkg:
# check that the daemon embeds the release update trust root, run the final
# verification (verify-pkg.sh --release, the oracle for the built bytes), and
# collect the .pkg, its checksum sidecar and SHA256SUMS into release/macos.
# Used by every workflow that signs a macOS build.
#
# Requires YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX; run from the repo root.

set -euo pipefail

: "${YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX:?YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX must be set}"

# The .pkg is the only official macOS artifact; no raw binary archive is built
# or published for it.
if ! grep -a -q "$YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX" target/release/yadorilink-daemon; then
    echo "yadorilink-daemon does not contain the configured update-manifest trust root -- it was not built with enforce-release-trust-root and the real key" >&2
    exit 1
fi

version="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)"
pkg="platforms/macos/package/dist/yadorilink-${version}.pkg"
test -f "$pkg" || { echo "signed pkg not found: $pkg" >&2; exit 1; }
pkgutil --check-signature "$pkg"
spctl -a -vvv -t install "$pkg"
# The signature and Gatekeeper checks above say nothing about whether the
# notarization ticket was stapled to the artifact. An unstapled .pkg passes
# both on the machine that built it, because Gatekeeper can still reach Apple
# to ask -- and then fails for a user who is offline or behind a filtering
# network. --release is what turns signature, Gatekeeper and stapling into
# hard failures rather than reported observations.
./platforms/macos/package/verify-pkg.sh --release "$pkg"
mkdir -p release/macos
cp "$pkg" "$pkg.sha256" release/macos/
python3 .github/release/collect-provenance.py "$pkg" "release/macos/yadorilink-${version}.pkg"
python3 .github/release/generate-release-checksums.py \
    --out release/macos/SHA256SUMS \
    "release/macos/yadorilink-${version}.pkg"
