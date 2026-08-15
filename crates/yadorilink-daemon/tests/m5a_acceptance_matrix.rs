//! M5-A Pass 8: the named, stable, CI-repeatable index of the multi-node
//! topology/relay/restart acceptance matrix. This file does not duplicate
//! any scenario's logic -- each scenario already lives in its own real
//! test file, several proven piecemeal well before this pass. This is the
//! single place that names all 20 and says where each one lives, plus a
//! freshness lint (matching `dst_runbook_freshness_lint.rs`'s established
//! idiom) that fails if this index and the actual test files drift apart.
//!
//! Scope: this matrix is specifically the multi-node topology/relay/
//! reconnect/restart resilience surface M5-A Passes 2-8 built out (real
//! `peer_orchestrator`, real transport, real DAG sync, on the canonical
//! N/M/W topology or its `ReconnectCoordinator`-focused variants). It does
//! NOT re-enumerate the daemon crate's much larger pre-existing test
//! suite (conflict-resolution matrices, DST fault-injection scenarios,
//! control-socket/IPC surface, etc.) -- those are real, valuable, and
//! already independently discoverable via `cargo test -p yadorilink-daemon`;
//! duplicating their listing here would be scope creep past what M5-A is
//! about and would go stale immediately.
//!
//! ## Deterministic release gate (20 scenarios)
//!
//! Every scenario below is deterministic (fixed small topology, no
//! seeded/randomized fault injection) and fast enough to run on every
//! change -- this is the full set `cargo test -p yadorilink-daemon` runs
//! by default (none of the 20 are `#[ignore]`d).
//!
//! 1. Direct happy-path convergence + hydration --
//!    `topology_n_m_w.rs::happy_path_direct_convergence_and_hydration`
//! 2. Direct fails -> relay fallback -> direct recovers --
//!    `topology_relay_failover.rs::direct_fails_falls_back_to_relay_then_direct_recovers`
//! 3. Multi-peer fan-in through one relay --
//!    `relay_chaos.rs::multi_peer_fan_in_through_one_relay`
//! 4. Opaque bytes flow source->relay->destination over the real wire --
//!    `relay_session_e2e.rs::opaque_bytes_flow_from_a_through_b_to_cs_real_address_over_the_real_wire`
//! 5. Requester's RelayCarrier opens a session via a real relay --
//!    `relay_session_e2e.rs::requester_relay_carrier_opens_a_session_and_forwards_via_a_real_relay`
//! 6. Full-replica anchor (N) restart never shows a stale Protected status --
//!    `topology_restart_convergence.rs::n_restart_never_shows_a_stale_protected_status`
//! 7. M restart recovers and resyncs with both peers --
//!    `topology_restart_convergence.rs::m_restart_recovers_and_resyncs_with_both_peers`
//! 8. W restart recovers and resyncs with both peers --
//!    `topology_restart_convergence.rs::w_restart_recovers_and_resyncs_with_both_peers`
//! 9. N restart mid-transfer still converges exactly --
//!    `topology_restart_convergence.rs::n_restart_mid_transfer_still_converges_exactly`
//! 10. W restart while relayed gets a fresh epoch, not a stale one --
//!     `topology_restart_while_relayed.rs::w_restart_while_relayed_gets_a_fresh_epoch_not_a_stale_one`
//! 11. relay-anchor-restart: N restarts mid relay-carried session --
//!     `topology_relay_role_restart_matrix.rs::relay_anchor_restart_mid_session`
//! 12. requester-restart-mid-relay: W (sender) restarts mid relay-carried
//!     session --
//!     `topology_relay_role_restart_matrix.rs::requester_restart_mid_relay_session`
//! 13. destination-restart-mid-relay: W (receiver) restarts mid relay-carried
//!     session --
//!     `topology_relay_role_restart_matrix.rs::destination_restart_mid_relay_session`
//! 14. Fan-in survives repeated connectivity flapping --
//!     `topology_relay_fan_in_reconnect_chaos.rs::fan_in_survives_repeated_connectivity_flapping`
//! 15. simultaneous-reconnect-fan-in: two peers lose and regain connectivity
//!     at once, each authoring offline content, both fan in without loss --
//!     `topology_simultaneous_reconnect_and_relay_hydration_failure.rs::simultaneous_reconnect_fan_in`
//! 16. relay-failure-during-hydration: relay capability revoked mid-fetch
//!     fails closed, recovers on retry --
//!     `topology_simultaneous_reconnect_and_relay_hydration_failure.rs::relay_failure_during_hydration`
//! 17. Safe demotion succeeds when a real peer durably holds everything --
//!     `topology_storage_mode_safety.rs::safe_demotion_succeeds_when_a_real_peer_durably_holds_everything`
//! 18. A version change during lease issuance refuses the demotion (TOCTOU
//!     guard) --
//!     `topology_storage_mode_safety.rs::version_change_during_lease_issuance_refuses_the_demotion`
//! 19. Already-paired peers keep syncing after the coordination plane goes
//!     entirely unreachable --
//!     `chaos_coordination_unreachable.rs::peers_keep_syncing_after_coordination_plane_goes_unreachable`
//! 20. ReconnectCoordinator survives simultaneous multi-peer flapping,
//!     mid-sync revocation, supervisor restart, and a pathological peer
//!     without starving healthy ones -- `reconnect_coordinator_scenarios.rs::{ten_peers_flap_simultaneously, twenty_peers_lose_connection_simultaneously, reconnect_during_active_sync, reconnect_after_supervisor_restart, pathological_peer_does_not_starve_healthy_peers}`
//!
//! ## Randomized / soak lane (separate, M5-A Pass 9's scope)
//!
//! Not part of the deterministic gate above -- these are seeded,
//! randomized, or long-running by design and belong to a soak/nightly
//! lane, not every-change CI:
//! - `monkey_chaos.rs` (random multi-device concurrent-op convergence +
//!   `replay_known_failing_seeds` regression corpus)
//! - the `dst_*_chaos.rs` / `dst_*_sweep.rs` madsim fault-injection suites
//!   (network faults, disk faults, hydration-under-fault, directory chaos,
//!   watcher/debounce chaos, three-device mesh chaos, etc.)
//! - `row14_strict_acceptance.rs::row14_strict_acceptance` (6-device,
//!   10-round staggered edit/delete/rename convergence under a strict
//!   stall bound -- deterministic in outcome but heavy enough to belong
//!   with the soak lane rather than the fast gate)

use std::collections::BTreeSet;
use std::path::PathBuf;

fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Every scenario pointer named in this file's own module doc comment
/// above (the numbered list, items 1-20 plus the reconnect-coordinator
/// group's five sub-scenarios), parsed straight out of the comment text
/// itself so the check is against what's actually WRITTEN here, not a
/// separately-maintained copy of the same list. A pointer is a
/// backtick-wrapped token of the shape test-file.rs::function-name, or
/// test-file.rs::{a, b, c} for a group of names in one file.
fn scenario_pointers_from_this_file() -> Vec<(String, String)> {
    let source = std::fs::read_to_string(tests_dir().join("m5a_acceptance_matrix.rs"))
        .expect("must be able to read its own source");
    let mut out = Vec::new();
    for line in source.lines() {
        // Skip this function's own doc comment lines -- they describe the
        // pointer shape using the shape itself as a literal example,
        // which would otherwise be mistaken for a real pointer.
        if line.contains("scenario pointer") || line.contains("backtick-wrapped") {
            continue;
        }
        let trimmed = line.trim_start_matches("//!").trim_start_matches("///").trim();
        let mut rest = trimmed;
        while let Some(start) = rest.find('`') {
            let after = &rest[start + 1..];
            let Some(end) = after.find('`') else { break };
            let token = &after[..end];
            if let Some((file_part, fn_part)) = token.split_once(".rs::") {
                let file_name = format!("{file_part}.rs");
                if fn_part.starts_with('{') {
                    for name in fn_part.trim_matches(|c| c == '{' || c == '}').split(',') {
                        out.push((file_name.clone(), name.trim().to_string()));
                    }
                } else {
                    out.push((file_name, fn_part.to_string()));
                }
            }
            rest = &after[end + 1..];
        }
    }
    out
}

#[test]
fn every_named_scenario_file_exists() {
    let pointers = scenario_pointers_from_this_file();
    assert!(
        !pointers.is_empty(),
        "failed to parse any scenario pointers out of this file's own doc comment"
    );
    let dir = tests_dir();
    let missing: Vec<_> = pointers
        .iter()
        .map(|(file, _)| file)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|file| !dir.join(file).is_file())
        .collect();
    assert!(
        missing.is_empty(),
        "m5a_acceptance_matrix.rs names test files that no longer exist under tests/: {missing:?}"
    );
}

#[test]
fn every_named_scenario_function_exists_in_its_file() {
    let pointers = scenario_pointers_from_this_file();
    let dir = tests_dir();
    let mut missing = Vec::new();
    for (file, function) in &pointers {
        let source = std::fs::read_to_string(dir.join(file))
            .unwrap_or_else(|e| panic!("cannot read tests/{file}: {e}"));
        let needle = format!("fn {function}(");
        if !source.contains(&needle) {
            missing.push(format!("{file}::{function}"));
        }
    }
    assert!(
        missing.is_empty(),
        "m5a_acceptance_matrix.rs names scenarios that no longer exist as written: {missing:?}"
    );
}
