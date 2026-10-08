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
# fails CI when a new ignored test is not registered here, and — since this
# file is `set -e` and the first entry aborts the whole run — when an entry
# names a package, target or test that no longer exists.
run_exact_ignored yadorilink-daemon test load_many_small_files \
  many_small_files_survive_initial_sync_and_incremental_update
run_exact_ignored yadorilink-daemon test live_burst_batching \
  live_burst_of_many_small_files_converges_via_debounced_batching
# The compression cost benchmark lives in yadorilink-peer-session, which
# includes peer_session.rs as `peer_session_impl`.
run_exact_ignored yadorilink-peer-session lib - \
  peer_session_impl::compression_benchmark::bytes_on_wire_and_cost_source_tree_vs_media

# --- Scale and cost benchmarks -------------------------------------------
#
# Each asserts a shape (linear, flat, indifferent to an unrelated group)
# rather than an absolute number, so they are meaningful on a soak runner
# without being pinned to one machine's speed.
run_exact_ignored yadorilink-sync-sqlite lib - \
  native_summary_scaling_tests::summary_cost_at_100k_heads
run_exact_ignored yadorilink-sync-sqlite test rewind_plan_scale_benchmark \
  compute_rewind_plan_scales_linearly_with_the_groups_own_path_count
run_exact_ignored yadorilink-sync-sqlite test rewind_plan_scale_benchmark \
  compute_rewind_plan_is_indifferent_to_unrelated_group_size
run_exact_ignored yadorilink-sync-sqlite test rewind_plan_scale_benchmark \
  compute_rewind_plan_is_indifferent_to_unrelated_paths_history_depth
run_exact_ignored yadorilink-sync-sqlite test root_set_generation_write_cost \
  the_generation_triggers_cost_the_import_path_this_much
run_exact_ignored yadorilink-sync-sqlite test root_set_generation_write_cost \
  the_local_summary_is_linear_and_the_memo_key_is_flat

# --- Long real-time proofs -----------------------------------------------
#
# Both say "run explicitly, not in ordinary CI" in their own #[ignore]
# reason. This soak workflow IS that explicit run; excluding them from it
# leaves them running nowhere, which is what "not in ordinary CI" was never
# meant to mean.
run_exact_ignored yadorilink-daemon test retirement_backstop_group_deauthorization \
  manually_registered_session_survives_the_retirement_backstop

# --- Environment probe ----------------------------------------------------
#
# Asserts nothing; it reports what this host's filesystem can say about file
# identity. Worth running on the soak box precisely because that answer is
# per-machine, and --nocapture puts it in the log.
run_exact_ignored yadorilink-root-authority test identity_probe \
  report_what_this_filesystem_can_say_about_identity

# --- Local network ---------------------------------------------------------
#
# Real mDNS between two endpoints on one host. Ignored in ordinary CI because
# hosted runners often do not deliver multicast to themselves; the soak box is
# a machine that does.
run_exact_ignored yadorilink-sync-substrate lib - \
  lan::tests::two_authorized_endpoints_find_each_other_over_real_mdns
