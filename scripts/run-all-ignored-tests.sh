#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

run_exact_ignored() {
  local package="$1"
  local target_kind="$2"
  local target="$3"
  local test_name="$4"
  local -a cargo_args=(-p "$package")

  if [[ "$target_kind" == "lib" ]]; then
    cargo_args+=(--lib)
  else
    cargo_args+=(--test "$target")
  fi

  local listed
  listed="$(cargo test "${cargo_args[@]}" -- --ignored --list)"
  if ! grep -Fqx "${test_name}: test" <<<"$listed"; then
    echo "ignored test was not discovered: ${package} ${target_kind} ${target} ${test_name}" >&2
    exit 1
  fi

  cargo test "${cargo_args[@]}" -- --ignored --exact "$test_name" --nocapture
}

# Keep one explicit entry for every #[ignore] test. scripts/check-test-inventory.py
# fails CI when a new ignored test is not registered here.
run_exact_ignored yadorilink-sync-core lib - \
  peer_session::compression_benchmark::bytes_on_wire_and_cost_source_tree_vs_media
run_exact_ignored yadorilink-transport test tunnel_longevity \
  tunnel_rekeys_and_keeps_delivering
run_exact_ignored yadorilink-transport test tunnel_longevity \
  session_survives_a_peer_roaming_to_a_new_address
run_exact_ignored yadorilink-daemon test load_many_small_files \
  many_small_files_survive_initial_sync_and_incremental_update
run_exact_ignored yadorilink-daemon test live_burst_batching \
  live_burst_of_many_small_files_converges_via_debounced_batching
