#!/usr/bin/env bash
# Generates a module-level "uses" dependency DOT graph for one workspace
# crate, via `cargo modules dependencies`.
#
# Usage:
#   scripts/gen-module-dependency-graph.sh <crate-name> full
#   scripts/gen-module-dependency-graph.sh <crate-name> collapsed
#
# "full" keeps every module at every depth. "collapsed" stops at depth 1
# (the crate's top-level modules), for a coarse overview.
#
# Only modules and their "uses" edges are shown (fns/types/traits/owns
# edges are filtered out) -- this is a module-references-module graph, not
# a function call graph.
set -euo pipefail

CRATE="${1:?usage: gen-module-dependency-graph.sh <crate-name> <full|collapsed>}"
MODE="${2:?usage: gen-module-dependency-graph.sh <crate-name> <full|collapsed>}"

ARGS=(dependencies -p "$CRATE" --lib --no-sysroot --no-externs --no-fns --no-types --no-traits --no-owns --layout dot)

case "$MODE" in
  full) ;;
  collapsed) ARGS+=(--max-depth 1) ;;
  *) echo "unknown mode: $MODE (expected full|collapsed)" >&2; exit 1 ;;
esac

cargo modules "${ARGS[@]}"
