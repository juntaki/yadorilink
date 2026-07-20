#!/usr/bin/env bash
#
# Generate the third-party license notice that ships with distributed artifacts.
# Emits a single self-contained HTML file listing every bundled third-party
# crate grouped by license, followed by the full text of each license.
#
# Usage:
#   scripts/generate-third-party-licenses.sh [OUTPUT]
#
# OUTPUT defaults to THIRD-PARTY-LICENSES.html at the repository root. The file
# is a build/packaging output and is not committed; installers and release
# packaging invoke this script to include it in the distributed artifact.
#
# Requires cargo-about:  cargo install cargo-about --locked
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

out="${1:-$repo_root/THIRD-PARTY-LICENSES.html}"

if ! command -v cargo-about >/dev/null 2>&1; then
  echo "error: cargo-about not found. Install with: cargo install cargo-about --locked" >&2
  exit 1
fi

# `--fail` turns any unresolved/unaccepted license into a non-zero exit so a new
# dependency carrying an unexpected license is caught rather than silently
# omitted from the notice.
cargo about generate --fail about.hbs -o "$out"

echo "Wrote third-party license notice: $out"
