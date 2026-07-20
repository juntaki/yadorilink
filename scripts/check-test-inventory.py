#!/usr/bin/env python3
"""Fail when a Rust test can silently fall out of the CI execution graph."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"
BETA_HEAT = ROOT / ".github/workflows/beta-heat.yml"
IGNORED_RUNNER = ROOT / "scripts/run-all-ignored-tests.sh"
CRATES = ROOT / "crates"
DST_CORPUS = (
    ROOT
    / "crates/yadorilink-sync-core/tests/dst_corpus/network_fault_chaos_cases.jsonl"
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
    # CLI end-to-end tests each drive at most one in-process daemon over a
    # per-test unix control socket in its own tempdir (or exercise pure CLI
    # parsing); deterministic, with no cross-test loopback/disk contention.
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
    "yadorilink-local-storage/tests/fs_backend.rs": "pure filesystem block-store over per-test tempdirs; no networking, reliable multi-threaded",
    # Transport tests bind their own ephemeral loopback ports per test and are
    # single-instance (not multi-daemon convergence), so they do not contend.
    "yadorilink-transport/tests/lan_discovery.rs": "single loopback-UDP discovery pair on its own ephemeral ports; not multi-daemon convergence",
    "yadorilink-transport/tests/peer_channel.rs": "direct loopback PeerChannel connect with per-test ephemeral keypairs/ports",
    "yadorilink-transport/tests/tunnel_longevity.rs": "soak cases are #[ignore] (scheduled beta lane); non-ignored cases are single loopback tunnels",
    # DAG store RED regression tests: each opens its own rusqlite
    # `Connection::open_in_memory()` and never touches the filesystem, a port,
    # or any other cross-test resource, so concurrent execution cannot flake.
    "yadorilink-sync-core/tests/dag_checkpoint_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-core/tests/dag_checkpoint_sequence_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-core/tests/dag_compaction_boundary_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-core/tests/dag_compaction_restart_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-core/tests/dag_frontier_ghost_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-core/tests/dag_frontier_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-core/tests/dag_orphan_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-core/tests/dag_prune_proof_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-core/tests/dag_retained_history_integrity_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-core/tests/dag_serving_authorization_red.rs": "isolated in-memory SQLite connection per test; no shared state",
    "yadorilink-sync-core/tests/dag_store_repair.rs": "isolated in-memory SQLite connection per test; no shared state",
}


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
    # lane0 covers the `cfg(not(madsim))` lint scenarios that lane1's madsim
    # build compiles to zero tests. Requiring both keeps every dst_*.rs covered.
    daemon_lane = (
        "cargo test -p yadorilink-daemon --tests -- --test-threads=1" in ci
    )
    dst_lane = (
        "cargo run -p xtask -- dst-lane0" in ci
        and "cargo run -p xtask -- dst-lane1" in ci
    )

    if not daemon_lane:
        failures.append(
            "ci.yml must run the whole daemon crate single-threaded: "
            "`cargo test -p yadorilink-daemon --tests -- --test-threads=1`"
        )
    if not dst_lane:
        failures.append(
            "ci.yml must run both per-PR DST lanes (`cargo run -p xtask -- "
            "dst-lane0` and `dst-lane1`) that together cover every sync-core "
            "dst_*.rs scenario"
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

        # (a) daemon whole-crate single-threaded lane
        if crate == "yadorilink-daemon" and daemon_lane:
            continue
        # (b) DST xtask lanes / scheduled sweep (all sync-core dst_*.rs)
        if crate == "yadorilink-sync-core" and stem.startswith("dst_") and dst_lane:
            continue
        # (a) sync-core wire single-threaded lane (named `--test <stem>`)
        if crate == "yadorilink-sync-core" and named_test(stem):
            continue
        # (c) explicit workspace-multithread allowlist
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


def ignored_tests() -> list[tuple[Path, int, str]]:
    found: list[tuple[Path, int, str]] = []
    attribute = re.compile(r"^\s*#\s*\[ignore(?:\s*=.*)?\]\s*$")
    function = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for path in sorted((ROOT / "crates").glob("**/*.rs")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not attribute.match(line):
                continue
            for candidate in lines[index + 1 : index + 8]:
                match = function.search(candidate)
                if match:
                    found.append((path, index + 1, match.group(1)))
                    break
            else:
                raise RuntimeError(f"{path}:{index + 1}: #[ignore] has no test function")
    return found


def main() -> int:
    failures: list[str] = []
    ci = CI.read_text(encoding="utf-8")
    beta_heat = BETA_HEAT.read_text(encoding="utf-8")
    ignored_runner = IGNORED_RUNNER.read_text(encoding="utf-8")

    if "cargo test --workspace" not in ci:
        failures.append("CI must run the complete non-ignored Rust workspace test suite")
    if "python3 scripts/check-test-inventory.py" not in ci:
        failures.append("CI must run scripts/check-test-inventory.py")
    if "scripts/run-all-ignored-tests.sh" not in beta_heat:
        failures.append("the scheduled beta workflow must run every ignored Rust test")

    failures.extend(reliable_lane_failures(ci))
    failures.extend(guard_script_failures(ci))

    for path, line, test_name in ignored_tests():
        if test_name not in ignored_runner:
            failures.append(
                f"{path.relative_to(ROOT)}:{line}: ignored test is not registered: {test_name}"
            )

    corpus_cases = [
        line
        for line in DST_CORPUS.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not corpus_cases:
        failures.append("DST regression corpus must contain at least one replay case")
    dst_scenario = (
        ROOT / "crates/yadorilink-sync-core/tests/dst_network_fault_chaos.rs"
    ).read_text(encoding="utf-8")
    if "for case in load_corpus_cases()" not in dst_scenario:
        failures.append("DST network chaos scenario must replay the checked-in corpus")

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
