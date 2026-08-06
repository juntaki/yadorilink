#!/usr/bin/env bash
# Regenerates the architecture dependency baseline: crate graph, per-crate
# module dependency graphs (full + collapsed), weighted module coupling
# graphs, and the dependency-rules.toml boundary overlay.
#
# Usage: architecture/scripts/generate-all.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/architecture/graphs/generated"
mkdir -p "$OUT"
cd "$ROOT"

SHA="$(git rev-parse --short HEAD)"

dot_to_svg() {
  dot -Tsvg "$1" -o "${1%.dot}.svg"
}

# Embeds the commit SHA into a cargo-modules generated graph's label
# (cargo-modules always writes label="<crate_name>").
stamp_sha() {
  local file="$1"
  sed -i.bak "s/label=\"\([^\"]*\)\",/label=\"\1 @ ${SHA}\",/" "$file"
  rm -f "${file}.bak"
}

# cargo-modules emits record-shaped nodes (label="pub mod|app"). Graphviz's
# `dot` layout drops edges between same-rank record nodes in a `rankdir=LR`
# graph ("Error: lost ... edge"), so flatten to plain box nodes with just
# the item name.
flatten_record_nodes() {
  local file="$1"
  sed -i.bak \
    -e 's/shape="record"/shape="box"/' \
    -e 's/label="[^|"]*|\([^"]*\)"/label="\1"/' \
    "$file"
  rm -f "${file}.bak"
}

echo "== workspace crate graph =="
python3 scripts/gen-workspace-crate-graph.py > "$OUT/workspace-crates.dot"
dot_to_svg "$OUT/workspace-crates.dot"

for crate in yadorilink-daemon yadorilink-sync-core; do
  short="${crate#yadorilink-}"

  echo "== $crate module graph (full) =="
  scripts/gen-module-dependency-graph.sh "$crate" full > "$OUT/${short}-modules-full.dot"
  stamp_sha "$OUT/${short}-modules-full.dot"
  flatten_record_nodes "$OUT/${short}-modules-full.dot"
  dot_to_svg "$OUT/${short}-modules-full.dot"

  echo "== $crate module graph (collapsed) =="
  scripts/gen-module-dependency-graph.sh "$crate" collapsed > "$OUT/${short}-modules-collapsed.dot"
  stamp_sha "$OUT/${short}-modules-collapsed.dot"
  flatten_record_nodes "$OUT/${short}-modules-collapsed.dot"
  dot_to_svg "$OUT/${short}-modules-collapsed.dot"

  echo "== $crate module coupling =="
  python3 scripts/gen-module-coupling-graph.py "$crate" "crates/$crate/src" > "$OUT/${crate}-coupling.dot"
  dot_to_svg "$OUT/${crate}-coupling.dot"
done

echo "== dependency boundary overlay =="
python3 scripts/gen-dependency-boundary-graph.py \
  architecture/dependency-rules.toml \
  "$OUT/workspace-crates.dot" \
  "$OUT/yadorilink-daemon-coupling.dot" \
  "$OUT/yadorilink-sync-core-coupling.dot" \
  > "$OUT/dependency-boundaries.dot"
dot_to_svg "$OUT/dependency-boundaries.dot"

echo "== yadorilink-daemon production graph (test code excluded) =="
python3 scripts/gen-daemon-production-graph.py yadorilink-daemon crates/yadorilink-daemon/src \
  > "$OUT/daemon-production.dot"
dot_to_svg "$OUT/daemon-production.dot"

echo "== yadorilink-daemon SCC condensation + hotspots =="
python3 scripts/gen-scc-condensation.py "$SHA" "$OUT/daemon-production.dot" \
  --condensed-out "$OUT/daemon-scc-condensed.dot" \
  --summary-out "$OUT/daemon-scc-summary.json" \
  --hotspot "daemon_state=$OUT/daemon-hotspot-daemon-state.dot" \
  --hotspot "control_socket=$OUT/daemon-hotspot-control-socket.dot" \
  --hotspot "peer_registry=$OUT/daemon-hotspot-peer-registry.dot" \
  --hotspot "link_registry=$OUT/daemon-hotspot-link-registry.dot"
dot_to_svg "$OUT/daemon-scc-condensed.dot"
dot_to_svg "$OUT/daemon-hotspot-daemon-state.dot"
dot_to_svg "$OUT/daemon-hotspot-control-socket.dot"
dot_to_svg "$OUT/daemon-hotspot-peer-registry.dot"
dot_to_svg "$OUT/daemon-hotspot-link-registry.dot"

echo "done -> $OUT"
