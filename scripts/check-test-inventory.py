#!/usr/bin/env python3
"""Fail when a Rust test can silently fall out of the CI execution graph."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI_FILES = [
    path
    for path in (
        ROOT / ".github/workflows/ci.yml",
        ROOT / ".github/workflows/ci-fast.yml",
        ROOT / ".github/workflows/ci-full.yml",
        ROOT / "oss-public/.github/workflows/ci-fast.yml",
        ROOT / "oss-public/.github/workflows/ci-full.yml",
    )
    if path.exists()
]
BETA_HEAT = ROOT / ".github/workflows/beta-heat.yml"
IGNORED_RUNNER = ROOT / "scripts/run-all-ignored-tests.sh"
CRATES = ROOT / "crates"
DST_CORPUS = (
    # The shared DST corpus lives beside the daemon workflow/E2E scenarios
    # in `yadorilink-daemon`.
    ROOT
    / "crates/yadorilink-daemon/tests/dst_corpus/network_fault_chaos_cases.jsonl"
)

# Integration test files (`crates/*/tests/*.rs`) for which running only in the
# multi-threaded `cargo test --workspace` job is acceptable, i.e. they do NOT
# need a single-threaded reliable lane. Each entry needs a one-line reason
# explaining why concurrency does not make it flaky. Keyed by the path relative
# to `crates/`. A new integration file that is neither in a reliable
# single-threaded lane nor a DST xtask lane and is not listed here fails the
# guard, so a flake-prone test can never silently live only in the
# multi-threaded workspace run.
WORKSPACE_MULTITHREAD_ALLOWLIST: dict[str, str] = {
    # Client-core and desktop-app tests: each binary runs in its own process
    # and only mutates env vars of that process (serialized in-file by a
    # lock), against a stand-in socket or a HOME inside its own tempdir.
    "yadorilink-client-core/tests/client_core_facade.rs": "stand-in daemon on a tempdir unix socket; env set per process under an in-file lock",
    "yadorilink-client-core/tests/daemon_control_client.rs": "stand-in daemon on a tempdir unix socket; env set per process under an in-file lock",
    "yadorilink-desktop-app/tests/config_dir_matches_daemon.rs": "one test; HOME points at its own tempdir; pure path resolution",
    # Pure in-memory SQLite fuzz: every seed builds its own private
    # ReplicaCoordinators, no network, no shared filesystem, no globals —
    # fully deterministic and safe alongside any other test. (The
    # `ReplicaCoordinator` is constructed via a dev-dependency back-edge,
    # the same shape as `dag_store`'s own test fixtures in this crate.)
    "yadorilink-sync-sqlite/tests/dag_admission_order_fuzz.rs": "self-contained in-memory SQLite states per seed; no network/disk/global contention",
    # CLI end-to-end tests each drive at most one in-process daemon over a
    # per-test unix control socket in its own tempdir (or exercise pure CLI
    # parsing); deterministic, with no cross-test loopback/disk contention.
    # Wire-contract round trips against a locally started deployment. Every
    # test returns immediately unless YADORILINK_WIRE_CONTRACT_ADDR names one,
    # so the workspace run compiles this file and executes nothing.
    "yadorilink-cli/tests/coordination_wire_contract.rs": "inert without YADORILINK_WIRE_CONTRACT_ADDR; its own lane runs it alone and single-threaded",
    "yadorilink-cli/tests/cli_output_golden.rs": "runs the CLI binary as a child against an optional in-process daemon on a per-test unix socket; daemon cases serialize on a mutex",
    "yadorilink-cli/tests/desktop_status_parity.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    "yadorilink-cli/tests/diagnose.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    "yadorilink-cli/tests/gc.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    "yadorilink-cli/tests/ignore.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    "yadorilink-cli/tests/limits.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    "yadorilink-cli/tests/link_library_surface.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    "yadorilink-cli/tests/materialization.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    "yadorilink-cli/tests/recovery_model.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    "yadorilink-cli/tests/report.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    "yadorilink-cli/tests/update.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    "yadorilink-cli/tests/version_history.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    # Non-UI half of the tray app, same in-process-daemon-over-control-socket
    # harness as the CLI tests above.
    "yadorilink-desktop-app/tests/status_app_ipc.rs": "single in-process daemon over a per-test unix control socket; no cross-test contention",
    # Pure on-disk block-store tests over per-test tempdirs; no networking.
    # `fs_backend.rs` was replaced by the four segment-store files when the
    # loose store gave way to the segment store; the entry stayed behind
    # pointing at a deleted file while its four successors went unregistered.
    "yadorilink-local-storage/tests/segment_block_store.rs": "pure filesystem block-store over per-test tempdirs; no networking, reliable multi-threaded",
    "yadorilink-local-storage/tests/segment_store_corruption.rs": "pure filesystem block-store over per-test tempdirs; no networking, reliable multi-threaded",
    "yadorilink-local-storage/tests/segment_store_crash.rs": "pure filesystem block-store over per-test tempdirs; no networking, reliable multi-threaded",
    "yadorilink-local-storage/tests/segment_store_startup.rs": "pure filesystem block-store over per-test tempdirs; no networking, reliable multi-threaded",
    # The history-base epoch reference model and its seal-theorem
    # properties: a pure, total state machine over `BTreeMap`s with no
    # filesystem, network, database, clock or global state of any kind, so
    # nothing about it can depend on what else is running. It lives in
    # `tests/` rather than `src/` so it is not part of the published crate.
    "yadorilink-replica-domain/tests/history_epoch_model.rs": "pure in-memory state machine enumerated per case; no IO, no clock, no globals",
    # The production namespace projection checked against the same pure
    # reference model: in-memory enumeration only, nothing shared.
    "yadorilink-replica-engine/tests/namespace_projection_model_differential.rs": "pure in-memory enumeration against the reference model; no IO, no clock, no globals",
    # Encodes and decodes change buffers in memory: no database, no socket, no
    # shared fixture, so it is indifferent to what else is running.
    "yadorilink-replica-domain/tests/change_generation_red.rs": "in-memory encode/decode of one change buffer; no IO, no globals",
    # Pure algorithm over in-memory state: no socket, no file, no global. The
    # RBSR suites build their own item sets per case and the protocol/runtime
    # suites wire two in-process peers over channels rather than a transport.
    "yadorilink-rbsr/tests/adversarial.rs": "pure in-memory reconciliation over per-case item sets; no IO at all",
    "yadorilink-rbsr/tests/convergence.rs": "pure in-memory reconciliation over per-case item sets; no IO at all",
    "yadorilink-sync-protocol/tests/base_negotiation.rs": "two in-process peers over an in-memory duplex pipe; no socket, no file, no global",
    "yadorilink-sync-protocol/tests/end_to_end.rs": "two in-process peers over channels; no socket, no file, no global",
    "yadorilink-sync-runtime/tests/two_node_convergence.rs": "two in-process peers over channels; no socket, no file, no global",
    # Per-test tempdir, synchronous recovery path, no runtime and no network
    # (see the file's own scope note for why it is deliberately not a
    # simulation scenario).
    "yadorilink-filesystem-sync/tests/dst_eviction_crash_recovery.rs": "synchronous recovery over a per-test tempdir; no runtime, no networking",
    # Reports what the local filesystem can say about file identity. Its one
    # test is `#[ignore]`d and run by the ignored-test runner, so the
    # workspace job only compiles it.
    "yadorilink-root-authority/tests/identity_probe.rs": "single #[ignore]d probe; the workspace job compiles it and runs nothing",
    "yadorilink-cli/tests/connections.rs": "single in-process daemon over a per-test unix socket; no cross-test contention",
    # Transport tests bind their own ephemeral loopback ports per test and are
    # single-instance (not multi-daemon convergence), so they do not contend.
    # DAG store RED regression tests: each opens its own rusqlite
    # `Connection::open_in_memory()` and never touches the filesystem, a port,
    # or any other cross-test resource, so concurrent execution cannot flake.
    "yadorilink-sync-sqlite/tests/dag_checkpoint_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-sqlite/tests/dag_checkpoint_sequence_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-sqlite/tests/dag_compaction_boundary_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-sqlite/tests/dag_compaction_restart_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-sqlite/tests/dag_frontier_ghost_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-sqlite/tests/dag_frontier_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-sqlite/tests/dag_orphan_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-sqlite/tests/dag_prune_proof_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-sqlite/tests/dag_retained_history_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-sqlite/tests/dag_serving_authorization_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-sqlite/tests/dag_store_repair.rs": "isolated in-memory SQLite connection per test; no shared state",
    # `VerifiedRoot`/`RootCommitPermit` exercised against a real
    # `ReplicaCoordinator`: every test opens its own `tempfile::tempdir()` root
    # and its own `ReplicaCoordinator::open`/`open_in_memory` instance, so
    # there is no shared filesystem path, port, or global state across
    # tests — including the deliberately concurrent
    # `concurrent_adoption_of_the_same_unmarked_root_never_
    # disagrees_with_itself`, whose 8-way race is internal to that one
    # test's own threads/barrier, not against any other test.
    "yadorilink-root-authority/tests/root_identity_verification.rs": "isolated per-test tempdir + own ReplicaCoordinator instance; no shared state across tests",
    # `LocalChangeProcessor` scan-after-repair seam test: its own tempdir for the
    # materialized root, own `tempfile::tempdir()` block store, own
    # `ReplicaCoordinator::open_in_memory()` instance; no shared state
    # across tests (single test in this file today).
    "yadorilink-local-capture/tests/materialization_local_capture.rs": "isolated per-test tempdir + own ReplicaCoordinator instance; no shared state across tests",
    "yadorilink-local-capture/tests/snapshot_install_disk_safety.rs": "isolated per-test tempdir + own in-memory ReplicaCoordinator; no network, no globals",
    # Crash-injection scenario for `repair_interrupted_materializations` +
    # `cleanup_stale_temp_files` (independent of the `dst_support` harness --
    # not simulation-gated, just seeded and run across many variations
    # in-process):
    # every variation builds its own tempdir root, own `FsBlockStore`, own
    # in-memory `ReplicaCoordinator`; no shared filesystem path, port, or
    # global state.
    "yadorilink-filesystem-sync/tests/dst_materialization_crash_recovery.rs": "isolated per-variation tempdir + own ReplicaCoordinator/FsBlockStore instances; no shared state across tests",
    # Authorization-Server client tests. Each case starts its own `wiremock`
    # MockServer on an ephemeral port and its own `tempfile::tempdir()`
    # credential store, and nothing here reads or writes a process-global: no
    # `set_var`, no fixed port, no shared config directory. The two files that
    # genuinely depend on real elapsed time and real process scheduling --
    # `cross_process_rotation.rs` and `five_minute_boundary.rs` -- are not here;
    # they have their own single-threaded lane (see AUTH_RUNTIME_LANE), which is
    # the distinction this allowlist exists to make.
    "yadorilink-fapi-client/tests/bootstrap_enrolment.rs": "per-test wiremock server on an ephemeral port; the polling loop's sleep is injected, so no case waits on a clock",
    "yadorilink-fapi-client/tests/credential_manager.rs": "per-test wiremock server on an ephemeral port + per-test tempdir store; no globals, no fixed ports",
    # The server-profile and token-response contracts: each case stands up its
    # own wiremock server on an ephemeral port, serves one doctored document or
    # token response to one client, and asserts on the refusal. No clock, no
    # disk beyond a per-test tempdir, no shared fixture.
    "yadorilink-fapi-client/tests/server_profile.rs": "per-test wiremock server on an ephemeral port; one doctored discovery document per case, no shared state",
    "yadorilink-fapi-client/tests/token_response_contract.rs": "per-test wiremock server on an ephemeral port; one doctored token response per case, no shared state",
    "yadorilink-fapi-client/tests/registration_status.rs": "per-test wiremock server on an ephemeral port + per-test tempdir store; one doctored token-endpoint refusal per case, no shared state",
    # Three entries used to sit here -- `negatives.rs`, `vertical_flow.rs` and
    # `store_backed_client.rs` -- gated on YADORILINK_AS_BASE_URL, which named a
    # SECOND Authorization Server: a prototype with its own provider, its own
    # storage and a client registration written straight into its database by a
    # script. All three files, and the server they dialled, are deleted. The
    # FAPI negatives they carried now run in
    # `yadorilink-cli/tests/coordination_wire_contract.rs` against the real
    # composition root, with a client obtained by actually enrolling.
}


# The `auth-runtime-boundaries` lane, pinned as one exact command rather than
# as two independent name lookups.
#
# What is being protected is a conjunction: both proofs, in the same
# invocation, single-threaded. Checking the parts separately would keep passing
# after someone split the lane across two multi-threaded jobs, or dropped the
# `--test-threads=1` -- and `cross_process_rotation`'s control case is a control
# only as long as it owns the machine it runs on.
#
# These two files are the only place in this workspace where the Coordination
# credential is exercised as a *runtime* object rather than as arithmetic: that
# a process is still authenticated after the deployment's own 300-second access
# token has died, and that two processes rotating one refresh token cannot
# destroy the grant family. Both were added as security proofs. A security proof
# that is not in the execution graph proves nothing continues to hold, so
# removing either invocation has to fail this gate.
AUTH_RUNTIME_LANE = (
    "cargo test -p yadorilink-fapi-client "
    "--test cross_process_rotation "
    "--test five_minute_boundary "
    "-- --test-threads=1"
)
AUTH_RUNTIME_TESTS = ("cross_process_rotation", "five_minute_boundary")

# The broad `cargo test --workspace` runs must skip the lane's cases by their
# FULL names, so the lane owns them instead of every platform job paying the
# boundary test's 320 seconds of deliberate sleeping over again.
#
# Full names, not a shared prefix: `--skip` is a substring match against the
# whole test path, so the obvious `--skip rotation_` also silently drops
# `credential_manager.rs`'s
# `a_second_process_cannot_refresh_while_the_first_holds_the_rotation_lock` --
# a lock test that is NOT in the lane and would have stopped running anywhere.
# That is why the rule below is computed from the files rather than written out:
# a test added to or renamed in either lane file has to appear in every
# workspace run's skip list, or it runs in both places or in neither, and both
# of those go unnoticed.
WORKSPACE_RUN = re.compile(r"cargo test[^\n]*--workspace")


def auth_runtime_tests_in(stem: str) -> list[str]:
    """The test functions defined in one of the two lane files."""
    path = CRATES / "yadorilink-fapi-client" / "tests" / f"{stem}.rs"
    lines = path.read_text(encoding="utf-8").splitlines()
    names: list[str] = []
    for index, line in enumerate(lines):
        if not re.match(r"^\s*#\[(tokio::)?test\b", line):
            continue
        for candidate in lines[index + 1 :]:
            match = FUNCTION_DEFINITION.match(candidate)
            if match:
                names.append(match.group(1))
                break
            if candidate.startswith("}"):
                break
    return names


def workspace_skip_failures(ci: str) -> list[str]:
    """Every workspace-wide `cargo test` run must skip the lane's cases."""
    failures: list[str] = []
    expected = [name for stem in AUTH_RUNTIME_TESTS for name in auth_runtime_tests_in(stem)]
    if not expected:
        return [
            "the auth-runtime-boundaries lane files define no test functions; "
            "the skip rule below would be vacuous"
        ]

    for path in CI_FILES:
        text = path.read_text(encoding="utf-8")
        for step in re.split(r"\n\s*- (?:name|run|uses):", text):
            flat = " ".join(step.split())
            if not WORKSPACE_RUN.search(flat):
                continue
            missing = [name for name in expected if f"--skip {name}" not in flat]
            if missing:
                failures.append(
                    f"{path.relative_to(ROOT)}: a `cargo test --workspace` run does not skip "
                    f"{', '.join(missing)}. The auth-runtime-boundaries lane owns these cases; "
                    "running them here as well spends the boundary test's 320 seconds of "
                    "deliberate real-time sleeping a second time on every platform"
                )
    return failures


def reliable_lane_failures(ci: str) -> list[str]:
    """Every `crates/*/tests/*.rs` file must run in a reliable lane: a
    single-threaded per-PR ci.yml lane, a DST xtask lane / scheduled sweep, or
    an explicit allowlist entry. Anything else fails so no RED regression test
    can silently escape into the flake-prone multi-threaded workspace run."""
    failures: list[str] = []

    # Lane-enabling markers, matched against the actual `run:` command strings
    # (not bare names that could appear in a comment). The daemon lane runs the
    # WHOLE daemon crate single-threaded (`--tests` = unit + every integration
    # binary), so any daemon integration file is covered automatically. The two
    # DST xtask lanes together run every sync-core `dst_*.rs` scenario: lane1
    # discovers them via the xtask's discover_scenarios() (`dst_*.rs` glob), and
    # lane0 covers the plain-build lint scenarios that lane1's simulation
    # build does not run. Requiring both keeps every dst_*.rs covered.
    # Crates whose whole test surface runs in one single-threaded invocation.
    # The set is derived from CI rather than hard-coded, so giving a crate a
    # lane is the thing that exempts it.
    #
    # Split on `cargo test` first and match within one invocation. A single
    # regex over the flattened file cannot do this: `.*` before
    # `--test-threads=1` runs past the end of the command it started in and
    # credits one lane's `--test-threads=1` to a different lane's `-p`.
    whole_crate_lanes = {
        match.group(1)
        for invocation in re.sub(r"\s+", " ", ci).split("cargo test")
        for match in [
            re.match(
                r"(?:\s+--[\w-]+(?:=\S+)?)*\s+-p\s+(yadorilink-[a-z-]+)\s+--tests\s+--\s+"
                r"(?:\S+\s+)*?--test-threads=1",
                invocation,
            )
        ]
        if match
    }
    daemon_lane = "yadorilink-daemon" in whole_crate_lanes
    private_monkey_lane = (
        "cargo test -p yadorilink-daemon --test monkey_chaos -- --test-threads=1"
        in BETA_HEAT.read_text(encoding="utf-8")
    )
    # The simulation lane. What has to be true is that *some* simulation lane
    # executes scenarios rather than merely type-checking them:
    # `simulation-build` runs `cargo check`, and a scenario that compiles and
    # never runs is indistinguishable from one that was deleted. Satisfied by
    # the xtask front end or by a direct turmoil `cargo test` of the
    # `dst_turmoil_*` scenarios.
    dst_lane = "cargo run -p xtask -- dst-lane" in ci or (
        "--cfg turmoil" in ci and "cargo test" in ci and "dst_turmoil_" in ci
    )
    # The lane's `run:` is a folded YAML block, so compare against the command
    # with its line breaks and indentation collapsed rather than against the
    # file's raw text.
    flattened_ci = re.sub(r"\s+", " ", ci)
    auth_runtime_lane = AUTH_RUNTIME_LANE in flattened_ci

    if not daemon_lane:
        failures.append(
            "ci.yml must run the whole daemon crate single-threaded: "
            "`cargo test -p yadorilink-daemon --tests -- --test-threads=1`"
        )
    if not private_monkey_lane:
        failures.append(
            "beta-heat.yml must run the monkey-chaos seed lane: "
            "`cargo test -p yadorilink-daemon --test monkey_chaos -- "
            "--test-threads=1`"
        )
    if not dst_lane:
        failures.append(
            "CI must EXECUTE simulation scenarios, not only type-check them: "
            "either an xtask DST lane (`cargo run -p xtask -- dst-lane...`) or "
            "a turmoil lane that `cargo test`s the `dst_turmoil_*` targets "
            "under `--cfg turmoil`. `simulation-build` is a `cargo check` and "
            "does not count -- a scenario that compiles and never runs is the "
            "exact way an earlier simulation suite was lost"
        )
    if not auth_runtime_lane:
        missing = [
            stem for stem in AUTH_RUNTIME_TESTS if f"--test {stem}" not in flattened_ci
        ]
        detail = (
            f"the lane no longer invokes {', '.join(missing)}"
            if missing
            else "both tests are named, but not in the pinned single-threaded "
            "form -- they must run in one invocation that ends `-- "
            "--test-threads=1`"
        )
        failures.append(
            "CI must run the auth-runtime-boundaries lane verbatim as "
            f"`{AUTH_RUNTIME_LANE}`: {detail}. These are the only runtime "
            "proofs that a Coordination credential outlives its own "
            "five-minute access token and that two processes cannot revoke "
            "the grant family by rotating it at once; unpinned, they leave "
            "CI without leaving a trace"
        )

    def named_test(stem: str) -> bool:
        # Whole-token match so a shorter stem cannot be credited by being a
        # prefix of a longer `--test <name>` already in the file (e.g. a future
        # `peer.rs` must not match `--test peer_session`).
        return re.search(rf"--test {re.escape(stem)}(?=\s|\\|$)", ci) is not None

    for path in sorted(CRATES.glob("*/tests/*.rs")):
        key = str(path.relative_to(CRATES))
        crate = path.relative_to(CRATES).parts[0]
        stem = path.stem

        # (a) a whole-crate single-threaded lane (`-p <crate> --tests --
        # --test-threads=1`), which covers unit tests and every integration
        # binary in one go.
        if crate in whole_crate_lanes:
            continue
        # (b) DST xtask lanes / scheduled sweep are not a per-file rule of
        # their own: the daemon's dst_*.rs scenarios are covered by rule (a)
        # above (which exempts the whole crate), and no
        # other crate's dst_*.rs file relies on the DST xtask lanes rather
        # than an explicit single-threaded lane or allowlist entry (e.g.
        # `yadorilink-filesystem-sync/tests/dst_materialization_crash_
        # recovery.rs` is deliberately not xtask-discovered -- see
        # its own module doc -- and is covered by rule (c) below instead).
        # `dst_lane` is still required and checked above (`ci.yml must run
        # both per-PR DST lanes`); it just no longer gates a per-file rule
        # here.
        # (a) peer-session wire single-threaded lane (named `--test <stem>`).
        # `peer_session.rs`/`crash_recovery.rs`/`dag_two_device_wire_
        # convergence.rs` run under a `--test <stem>` invocation that targets
        # `yadorilink-peer-session` in ci.yml.
        if crate == "yadorilink-peer-session" and named_test(stem):
            continue
        # (c) the auth-runtime-boundaries lane. Deliberately keyed on the whole
        # pinned command rather than on `named_test(stem)`: if the lane is
        # dismantled, these two files must be reported as homeless here as well
        # as by the lane check above, so the failure says both what was removed
        # and which proofs stopped running.
        if crate == "yadorilink-fapi-client" and stem in AUTH_RUNTIME_TESTS:
            if auth_runtime_lane:
                continue
            failures.append(
                f"{path.relative_to(ROOT)}: the auth-runtime-boundaries lane no longer runs "
                "this file, so this runtime proof is no longer in the CI execution graph"
            )
            continue
        # (d) explicit workspace-multithread allowlist
        if key in WORKSPACE_MULTITHREAD_ALLOWLIST:
            continue

        failures.append(
            f"{path.relative_to(ROOT)}: integration test file is not in any reliable "
            "lane — add it to a single-threaded ci.yml lane, a DST xtask lane, or "
            "WORKSPACE_MULTITHREAD_ALLOWLIST (with a one-line reason)"
        )

    # Keep the allowlist honest: a stale entry pointing at a deleted file must
    # be removed rather than lingering as unexplained dead config.
    for key in WORKSPACE_MULTITHREAD_ALLOWLIST:
        if not (CRATES / key).exists():
            failures.append(
                f"WORKSPACE_MULTITHREAD_ALLOWLIST entry has no file on disk: {key}"
            )

    return failures


def guard_script_failures(ci: str) -> list[str]:
    """Every repository guard must be reachable from the per-PR CI graph."""
    failures: list[str] = []
    for path in sorted((ROOT / "scripts").glob("check-*.py")):
        relative = path.relative_to(ROOT).as_posix()
        if f"python3 {relative}" not in ci:
            failures.append(f"{relative}: guard script is not invoked by ci.yml")
    return failures


# A function *definition* line, anchored at the start of the line. Anchoring is
# the point: an attribute's argument can contain the word `fn` inside a string
# (a multi-line `#[allow(..., reason = "...")]` routinely does), and an
# unanchored search credits that string as the test's name -- or, when the
# attribute is long enough, pushes the real `fn` out of a fixed lookahead
# window and turns the whole guard into a crash. Both happened; this pattern
# matches the item itself instead of anything that mentions one.
FUNCTION_DEFINITION = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?"
    r"(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?"
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)


def ignored_tests() -> list[tuple[Path, int, str]]:
    """Every `#[ignore]`d test in the tree, as (file, line, test name).

    An attribute applies to the item that follows it, and arbitrarily many
    further attributes -- of arbitrary length -- may sit in between. So this
    scans forward to the next function *definition* rather than peeking a fixed
    number of lines ahead, and stops at the end of the enclosing item so a
    dangling `#[ignore]` is still reported instead of being silently attributed
    to some unrelated function further down the file.
    """
    found: list[tuple[Path, int, str]] = []
    attribute = re.compile(r"^\s*#\s*\[ignore(?:\s*=.*)?\]\s*$")
    for path in sorted((ROOT / "crates").glob("**/*.rs")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not attribute.match(line):
                continue
            for candidate in lines[index + 1 :]:
                match = FUNCTION_DEFINITION.match(candidate)
                if match:
                    found.append((path, index + 1, match.group(1)))
                    break
                # Column-zero `}` closes the module or impl the attribute sits
                # in: there is no following function, so the attribute dangles.
                if candidate.startswith("}"):
                    raise RuntimeError(f"{path}:{index + 1}: #[ignore] has no test function")
            else:
                raise RuntimeError(f"{path}:{index + 1}: #[ignore] has no test function")
    return found


# An `#[ignore]`d test that `run-all-ignored-tests.sh` must NOT run, with the
# reason. The runner exists so no ignored test is quietly forgotten; a test
# that cannot run unattended does not become forgettable just because the
# runner would fail on it, so it is listed here explicitly rather than left
# to trip the registration check. Same shape and same honesty rule as
# WORKSPACE_MULTITHREAD_ALLOWLIST below: a stale entry naming a test that no
# longer exists is itself a failure.
IGNORED_RUNNER_EXEMPT: dict[str, str] = {
    "batch_position_probe": (
        "ad hoc diagnostic: requires DST_TARGET_SEED and panics without it, "
        "so an unattended sweep can only fail on it"
    ),
    "two_hosts_after_one_block_exchange": (
        "documents a limit that does NOT hold -- an established QUIC "
        "connection defeats turmoil's paused clock -- so running it can only "
        "fail. It is executable evidence for a comment, not a test"
    ),
    "transfer_1_gib": (
        "needs TMPDIR pointed at a spacious path; the soak workflow sets no "
        "such path and the runner's own disk is not one"
    ),
    "transfer_10_gib": "needs roughly 40 GiB free under TMPDIR",
    "fresh_seeds_converge_without_loss": (
        "KNOWN RED, not slow: the history-epoch fresh-seed sweep fails a share "
        "of seeds on the open P9-B findings (copy rows with no Gamma head, "
        "empty directories left after rm -rf / rename, the seed-41 seal "
        "fail-closed class) recorded in the compaction plan; the recorded "
        "corpus runs by default. Un-exempt and register it once those are fixed"
    ),
    "transfer_100_gib": "needs roughly 400 GiB free under TMPDIR",
    "sample_beta_manifest_fixture_verifies_against_the_shipped_trust_root": (
        "STALE, not slow: the fixture is signed over a schema-1 body and the "
        "manifest is at schema 2, so this fails until the fixture is "
        "re-signed. Exempted from the soak run, and recorded here so it is "
        "not mistaken for an expensive test"
    ),
}


def _runner_entry_sources(package: str, kind: str, target: str) -> list[Path] | None:
    """Where a registry entry's test function would have to be defined.

    `None` means the target itself does not exist, which is a separate and
    more specific finding than "the test is not in it".
    """
    crate = ROOT / "crates" / package
    if kind == "lib":
        lib_rs = crate / "src" / "lib.rs"
        if not lib_rs.is_file():
            return None
        return sorted((crate / "src").glob("**/*.rs"))
    target_rs = crate / "tests" / f"{target}.rs"
    if not target_rs.is_file():
        return None
    # An integration test target is one crate root, but it may pull the test
    # in from a module file next to it.
    return [target_rs] + sorted((crate / "tests").glob("**/*.rs"))


def ignored_runner_dead_entries(runner_text: str) -> list[str]:
    """Registry lines naming a package, target or test that no longer exists.

    The registration check above only runs in one direction: every
    `#[ignore]`d test must appear somewhere in the runner. Nothing checked
    the other way, and a deleted crate left a `run_exact_ignored` line
    behind that made the runner — which is `set -e` — abort on its first
    statement, so the scheduled soak workflow ran none of the tests it
    reported running. Nothing failed; the step just did nothing.

    All four fields are checked, not two. The first version of this check
    validated the package and, for `--test` targets only, the target file;
    it skipped `lib` entries entirely and never looked at the test name at
    all. That leaves the exact shape of the original outage uncovered: the
    entry that broke the runner named a `lib` target, and renaming a test
    without renaming its entry produces the identical `set -e` abort on a
    line the check would have called healthy.
    """
    failures: list[str] = []
    # Line continuations first: an entry is conventionally wrapped before the
    # test name, so the four fields are not all on one physical line.
    joined = re.sub(r"\\\n\s*", " ", runner_text)
    for match in re.finditer(
        # A leading environment assignment is part of the convention
        # (`RUSTFLAGS="--cfg turmoil" run_exact_ignored ...`), and an entry
        # carrying one must not slip past this check unread.
        r"^\s*(?:\w+=(?:\"[^\"]*\"|'[^']*'|\S*)\s+)*"
        r"run_exact_ignored\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)",
        joined,
        re.MULTILINE,
    ):
        package, kind, target, test = match.groups()
        if not (ROOT / "crates" / package).is_dir():
            failures.append(
                f"run-all-ignored-tests.sh registers a package that does not exist: {package}"
            )
            continue
        if kind not in ("lib", "test"):
            failures.append(
                "run-all-ignored-tests.sh registers an unknown target kind "
                f"(expected lib or test): {package} {kind} {target}"
            )
            continue
        sources = _runner_entry_sources(package, kind, target)
        if sources is None:
            described = "--lib" if kind == "lib" else f"--test {target}"
            failures.append(
                "run-all-ignored-tests.sh registers a target that does not exist: "
                f"{package} {described}"
            )
            continue
        # `--exact` takes the full module path; only the last segment is the
        # function's own name.
        bare = test.rsplit("::", 1)[-1]
        pattern = re.compile(r"\bfn\s+" + re.escape(bare) + r"\s*[(<]")
        if not any(pattern.search(path.read_text(encoding="utf-8")) for path in sources):
            described = "--lib" if kind == "lib" else f"--test {target}"
            failures.append(
                "run-all-ignored-tests.sh registers a test that no longer exists in its "
                f"target: {package} {described} -- {test}"
            )
    return failures


def main() -> int:
    failures: list[str] = []
    ci = "\n".join(path.read_text(encoding="utf-8") for path in CI_FILES)
    beta_heat = BETA_HEAT.read_text(encoding="utf-8")
    ignored_runner = IGNORED_RUNNER.read_text(encoding="utf-8")

    if "cargo test --workspace" not in ci:
        failures.append("CI must run the complete non-ignored Rust workspace test suite")
    if "python3 scripts/check-test-inventory.py" not in ci:
        failures.append("CI must run scripts/check-test-inventory.py")
    if "scripts/run-all-ignored-tests.sh" not in beta_heat:
        failures.append("the scheduled beta workflow must run every ignored Rust test")

    failures.extend(reliable_lane_failures(ci))
    failures.extend(workspace_skip_failures(ci))
    failures.extend(guard_script_failures(ci))
    failures.extend(ignored_runner_dead_entries(ignored_runner))

    seen_ignored: set[str] = set()
    for path, line, test_name in ignored_tests():
        seen_ignored.add(test_name)
        if test_name in IGNORED_RUNNER_EXEMPT:
            continue
        if test_name not in ignored_runner:
            failures.append(
                f"{path.relative_to(ROOT)}:{line}: ignored test is not registered: {test_name}"
            )
    # Keep the exemption list honest, the same way the multithread allowlist
    # is kept honest: an entry naming a test that no longer exists silently
    # widens the exemption for whatever is added under that name next.
    for test_name in IGNORED_RUNNER_EXEMPT:
        if test_name not in seen_ignored:
            failures.append(
                f"IGNORED_RUNNER_EXEMPT names no #[ignore]d test: {test_name}"
            )

    # The corpus must exist and must be replayed by *a* scenario. Which one is
    # not this guard's business: pinning it to
    # `dst_network_fault_chaos.rs::load_corpus_cases()` outlives that file, and
    # that file is on the retirement ledger. What matters is that a recorded
    # regression is replayed by something, rather than sitting in a JSONL
    # nobody reads.
    corpus_cases = [
        line
        for line in DST_CORPUS.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not corpus_cases:
        failures.append("DST regression corpus must contain at least one replay case")
    replayers = [
        path
        for path in sorted((ROOT / "crates/yadorilink-daemon/tests").glob("*.rs"))
        if "load_corpus_cases()" in path.read_text(encoding="utf-8")
    ]
    if not replayers:
        failures.append(
            f"no scenario replays the checked-in DST corpus ({DST_CORPUS.name}): a "
            "recorded regression that nothing replays is a file, not a test"
        )

    if failures:
        print("test inventory check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        f"test inventory: ok ({len(ignored_tests())} ignored tests registered, "
        f"{len(corpus_cases)} DST corpus cases)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
