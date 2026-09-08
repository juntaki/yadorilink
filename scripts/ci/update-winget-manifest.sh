#!/usr/bin/env bash
#
# scripts/ci/update-winget-manifest.sh
#
# Regenerates installer/windows/winget/manifests/j/juntaki/YadoriLink/<version>/
# for a new release: copies the previous version's three manifest files,
# substitutes PackageVersion/InstallerUrl/InstallerSha256, and leaves
# everything else (description, switches, ProductCode, ...) untouched --
# those only change when this repo's own packaging changes, not on every
# release.
#
# This is deliberately NOT wired to run automatically in
# oss-public/.github/workflows/release.yml and commit its own output: an
# unattended release workflow committing generated files back to this
# repository is exactly the kind of unattended action this project's
# release-signing discipline (required reviewers, no unattended
# production credentials) says should stay human-gated -- run it by hand
# and commit the result as a normal, reviewed change (see
# installer/windows/winget/README.md's Status section).
#
# Usage:
#   scripts/ci/update-winget-manifest.sh --version 0.2.0 --installer-sha256 <64-hex-chars>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MANIFESTS_ROOT="$REPO_ROOT/installer/windows/winget/manifests/j/juntaki/YadoriLink"

VERSION="" SHA256=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --installer-sha256) SHA256="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$VERSION" ] || [ -z "$SHA256" ]; then
  echo "usage: $0 --version X.Y.Z --installer-sha256 <64-hex-chars>" >&2
  exit 2
fi
if ! printf '%s' "$SHA256" | grep -Eq '^[0-9a-f]{64}$'; then
  echo "ERROR: --installer-sha256 must be exactly 64 lowercase hex characters, got: $SHA256" >&2
  exit 1
fi

# Base the new version's manifests on the most recently modified existing
# version directory (there is exactly one today: 0.1.0's placeholder) so a
# hand-authored field (Description, InstallerSwitches, ProductCode, Tags,
# ...) never has to be re-typed per release.
PREV_DIR="$(find "$MANIFESTS_ROOT" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -1)"
if [ -z "$PREV_DIR" ]; then
  echo "ERROR: no existing version directory under $MANIFESTS_ROOT to base the new manifest on" >&2
  exit 1
fi

NEW_DIR="$MANIFESTS_ROOT/$VERSION"
if [ -d "$NEW_DIR" ]; then
  echo "ERROR: $NEW_DIR already exists -- refusing to overwrite" >&2
  exit 1
fi
mkdir -p "$NEW_DIR"

for f in "$PREV_DIR"/*.yaml; do
  base="$(basename "$f")"
  sed \
    -e "s/^PackageVersion: .*/PackageVersion: ${VERSION}/" \
    -e "s#\(archive/refs/tags/v\)[^/]*\(\.tar\.gz\)#\1${VERSION}\2#" \
    -e "s#\(releases/download/v\)[^/]*/#\1${VERSION}/#" \
    -e "s/InstallerSha256: .*/InstallerSha256: \"${SHA256}\"/" \
    "$f" > "$NEW_DIR/$base"
done

echo "Wrote $NEW_DIR (from $PREV_DIR). Review the diff, then validate:"
echo "  python3 -c \"import yaml,json,jsonschema; ...\"  # see installer/windows/winget/README.md"
echo "  winget validate --manifest $NEW_DIR   # on a real Windows machine"
