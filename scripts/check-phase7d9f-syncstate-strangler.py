#!/usr/bin/env python3
"""Phase 7D-9F boundary gate: monotonic-decrease strangler-fig check for the
`SyncState`/`index.rs` facade (`crates/yadorilink-sync-core/src/index.rs`).

7D-9F is the last, largest sub-phase of Phase 7D-9 -- it retires the shared
`SyncState` facade every earlier 7D-9 sub-phase's still-in-transition code
calls through. `index.rs` is deliberately NOT moved in one shot; it shrinks
incrementally, pass by pass, as `docs/design/phase7d9f-syncstate-method-
ledger.toml` entries get migrated to their real destination crates. Per the
owning user's own explicit instruction ("gateに単調減少baselineを持たせる。
新しいmethod追加は禁止する" -- the gate must have a monotonic-decrease
baseline; adding new methods is forbidden), this script enforces that each
of four tracked metrics only ever goes down (or stays flat) from one pass to
the next, never up:

1. `SyncState` production method count -- every method-ledger entry whose
   `category` is not `test-only`/`dead` (those are not real production
   surface; a `dead` entry existing at all is itself something a future pass
   should delete, but its presence doesn't grow the *production* surface).
2. `SyncState` non-delegation method count -- production entries whose
   `category` is not `delegation` either (i.e. `composition`/`business
   logic`/`SQLite`/`filesystem` -- real logic still living on the facade,
   not a thin forward).
3. `index.rs` production line count -- total lines in the file minus every
   line inside a `#[cfg(test)]`-gated top-level item (test-only code
   shrinking or growing doesn't reflect facade-retirement progress either
   way).
4. Workspace-wide `Arc<SyncState>` occurrence count -- every crate that
   still needs to hold a live `SyncState` handle (a rough proxy for "how
   much of the workspace is still coupled to the facade's concrete type",
   counted textually across the whole workspace, tests included, since a
   test file holding one is still a real coupling point that has to go away
   eventually).

The baseline (the last-recorded values these metrics are allowed to be at or
below) lives in the small sidecar JSON file
`docs/design/phase7d9f-syncstate-strangler-baseline.json`, checked into git
so it persists across runs and across sessions -- not just a single-
invocation check. A normal run only *compares* against the baseline and
fails on regression; it never silently lowers the baseline itself (that
would hide real progress from the ledger/report, and would let a
mid-migration commit that hasn't finished updating the ledger quietly reset
the bar). Use `--update-baseline` to deliberately ratchet the baseline down
after a pass that made real progress and re-generated the method ledger to
match.

Same substring/regex-based approach as this repo's other phase-boundary
gate scripts (see `check-phase7d6-peer-session-boundary.py`,
`check-phase7d9-residual-ledger.py`) -- not a real Rust or TOML validator
beyond the standard library `tomllib` parse itself. Reviewer judgment
remains the backstop.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - repo's CI pins a modern python3
    import tomli as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
INDEX_RS = ROOT / "crates/yadorilink-sync-core/src/index.rs"
LEDGER_PATH = ROOT / "docs/design/phase7d9f-syncstate-method-ledger.toml"
BASELINE_PATH = ROOT / "docs/design/phase7d9f-syncstate-strangler-baseline.json"
WORKSPACE_SEARCH_DIRS = ("crates", "daemon")

KNOWN_CATEGORIES = {
    "delegation",
    "composition",
    "business logic",
    "SQLite",
    "filesystem",
    "test-only",
    "dead",
}
NON_PRODUCTION_CATEGORIES = {"test-only", "dead"}
DELEGATION_CATEGORIES = {"delegation"} | NON_PRODUCTION_CATEGORIES

METRIC_NAMES = (
    "syncstate_production_methods",
    "syncstate_non_delegation_methods",
    "index_rs_production_lines",
    "workspace_arc_syncstate_occurrences",
)


class GateError(Exception):
    pass


def load_ledger(ledger_path: Path) -> list[dict]:
    if not ledger_path.is_file():
        raise GateError(f"{ledger_path} does not exist")
    try:
        data = tomllib.loads(ledger_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise GateError(f"{ledger_path} is not valid TOML: {exc}") from exc
    entries = data.get("method")
    if entries is None:
        raise GateError(f"{ledger_path} defines no [[method]] entries")
    if not isinstance(entries, list):
        raise GateError(f"{ledger_path}'s 'method' key is not an array of tables")
    return entries


def ledger_failures(entries: list[dict]) -> list[str]:
    failures: list[str] = []
    seen_names: set[str] = set()
    for i, entry in enumerate(entries):
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            failures.append(f"method entry #{i} has no non-empty 'name'")
            continue
        if name in seen_names:
            failures.append(f"method {name!r}: duplicate ledger entry")
        seen_names.add(name)
        category = entry.get("category")
        if category not in KNOWN_CATEGORIES:
            failures.append(
                f"method {name!r}: unknown 'category' {category!r} -- expected one "
                f"of {sorted(KNOWN_CATEGORIES)}"
            )
        destination = entry.get("destination")
        if not isinstance(destination, list) or not destination:
            failures.append(f"method {name!r}: 'destination' is missing or empty")
        status = entry.get("status")
        if status not in ("pending", "migrated"):
            failures.append(
                f"method {name!r}: unknown 'status' {status!r} -- expected "
                "'pending' or 'migrated'"
            )
    return failures


def syncstate_method_counts(entries: list[dict]) -> tuple[int, int]:
    """(production_method_count, non_delegation_method_count), counting only
    entries not yet 'migrated' -- a migrated entry's method no longer lives
    on `SyncState`, so it shouldn't count against either metric."""
    production = 0
    non_delegation = 0
    for entry in entries:
        if entry.get("status") == "migrated":
            continue
        category = entry.get("category")
        if category in NON_PRODUCTION_CATEGORIES:
            continue
        production += 1
        if category not in DELEGATION_CATEGORIES:
            non_delegation += 1
    return production, non_delegation


def index_rs_production_lines(path: Path) -> int:
    if not path.is_file():
        # Phase 7D-10 completed the strangler by deleting sync-core. The
        # terminal metric is therefore zero, but a missing index.rs remains
        # an error if the retired crate itself has reappeared partially.
        if not path.parent.parent.exists():
            return 0
        raise GateError(f"{path} does not exist")
    lines = path.read_text(encoding="utf-8").splitlines()
    excluded = _cfg_test_line_ranges(lines)
    total = len(lines)
    excluded_count = sum(end - start for start, end in excluded)
    return total - excluded_count


def _cfg_test_line_ranges(lines: list[str]) -> list[tuple[int, int]]:
    """Half-open [start, end) 0-indexed line ranges covered by a top-level
    `#[cfg(test)]`-gated item (the attribute line itself through the item's
    matching closing brace)."""
    ranges: list[tuple[int, int]] = []
    i = 0
    n = len(lines)
    while i < n:
        if lines[i].strip() == "#[cfg(test)]":
            attr_start = i
            j = i + 1
            # skip any further attributes/comments before the item itself
            while j < n and (
                lines[j].strip().startswith("#[")
                or lines[j].strip().startswith("//")
                or not lines[j].strip()
            ):
                j += 1
            if j >= n:
                break
            depth = 0
            started = False
            k = j
            while k < n:
                depth += lines[k].count("{") - lines[k].count("}")
                if "{" in lines[k]:
                    started = True
                if started and depth == 0:
                    break
                k += 1
            item_end = min(k + 1, n)
            ranges.append((attr_start, item_end))
            i = item_end
            continue
        i += 1
    return ranges


def workspace_arc_syncstate_occurrences(root: Path) -> int:
    total = 0
    pattern = re.compile(r"Arc<SyncState>")
    for sub in WORKSPACE_SEARCH_DIRS:
        search_dir = root / sub
        if not search_dir.is_dir():
            continue
        for rs_file in search_dir.rglob("*.rs"):
            try:
                text = rs_file.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            total += len(pattern.findall(text))
    return total


def current_metrics(
    root: Path = ROOT, index_rs: Path = INDEX_RS, ledger_path: Path = LEDGER_PATH
) -> dict[str, int]:
    entries = load_ledger(ledger_path)
    production, non_delegation = syncstate_method_counts(entries)
    return {
        "syncstate_production_methods": production,
        "syncstate_non_delegation_methods": non_delegation,
        "index_rs_production_lines": index_rs_production_lines(index_rs),
        "workspace_arc_syncstate_occurrences": workspace_arc_syncstate_occurrences(root),
    }


def load_baseline(baseline_path: Path) -> dict[str, int]:
    if not baseline_path.is_file():
        raise GateError(
            f"{baseline_path} does not exist -- run with --update-baseline once "
            "to record the initial baseline"
        )
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GateError(f"{baseline_path} is not valid JSON: {exc}") from exc
    for metric in METRIC_NAMES:
        if metric not in data or not isinstance(data[metric], int):
            raise GateError(f"{baseline_path} is missing integer field {metric!r}")
    return {metric: data[metric] for metric in METRIC_NAMES}


def write_baseline(baseline_path: Path, metrics: dict[str, int]) -> None:
    payload = {metric: metrics[metric] for metric in METRIC_NAMES}
    baseline_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def regressions(current: dict[str, int], baseline: dict[str, int]) -> list[str]:
    failures = []
    for metric in METRIC_NAMES:
        if current[metric] > baseline[metric]:
            failures.append(
                f"{metric}: increased from baseline {baseline[metric]} to "
                f"{current[metric]} (a monotonic-decrease violation -- new "
                "SyncState methods/index.rs lines/Arc<SyncState> holders are "
                "forbidden; if this is a deliberate, reviewed exception, that "
                "decision belongs in the exit report, not a silent baseline "
                "bump)"
            )
    return failures


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "crates").mkdir()
        (root / "daemon").mkdir()
        index_rs = root / "index.rs"
        ledger_path = root / "ledger.toml"
        baseline_path = root / "baseline.json"

        def write_index_rs(body_lines: int, with_test_block: bool) -> None:
            lines = [f"// production line {i}" for i in range(body_lines)]
            if with_test_block:
                lines += [
                    "#[cfg(test)]",
                    "mod tests {",
                    "    fn a() {}",
                    "    fn b() {}",
                    "}",
                ]
            index_rs.write_text("\n".join(lines) + "\n", encoding="utf-8")

        def write_ledger(methods: list[dict]) -> None:
            chunks = []
            for m in methods:
                chunks.append("[[method]]")
                chunks.append(f'name = "{m["name"]}"')
                chunks.append(f'line = {m.get("line", 1)}')
                chunks.append(f'visibility = "{m.get("visibility", "pub")}"')
                chunks.append(f'category = "{m["category"]}"')
                dest = m.get("destination", ["yadorilink-sync-sqlite"])
                chunks.append(
                    "destination = [" + ", ".join(f'"{d}"' for d in dest) + "]"
                )
                chunks.append(f'production_callers = {m.get("production_callers", 0)}')
                chunks.append(f'status = "{m.get("status", "pending")}"')
                chunks.append("")
            ledger_path.write_text("\n".join(chunks), encoding="utf-8")

        base_methods = [
            {"name": "a", "category": "delegation"},
            {"name": "b", "category": "business logic"},
            {"name": "c", "category": "test-only"},
        ]

        # 1. Baseline creation via --update-baseline-equivalent call.
        write_index_rs(10, with_test_block=True)
        write_ledger(base_methods)
        metrics = current_metrics(root, index_rs, ledger_path)
        assert metrics["syncstate_production_methods"] == 2, metrics
        assert metrics["syncstate_non_delegation_methods"] == 1, metrics
        assert metrics["index_rs_production_lines"] == 10, metrics
        assert metrics["workspace_arc_syncstate_occurrences"] == 0, metrics
        write_baseline(baseline_path, metrics)
        baseline = load_baseline(baseline_path)
        assert baseline == metrics, (baseline, metrics)

        # 2. No change -> no regressions.
        current = current_metrics(root, index_rs, ledger_path)
        assert regressions(current, baseline) == []

        # 3. A migrated entry drops out of the production count.
        base_methods[1]["status"] = "migrated"
        write_ledger(base_methods)
        current = current_metrics(root, index_rs, ledger_path)
        assert current["syncstate_production_methods"] == 1, current
        assert current["syncstate_non_delegation_methods"] == 0, current
        assert regressions(current, baseline) == []
        base_methods[1]["status"] = "pending"
        write_ledger(base_methods)

        # 4. A brand-new production method must be caught as a regression.
        base_methods.append({"name": "d", "category": "delegation"})
        write_ledger(base_methods)
        current = current_metrics(root, index_rs, ledger_path)
        failures = regressions(current, baseline)
        assert any("syncstate_production_methods" in f for f in failures), failures
        base_methods.pop()
        write_ledger(base_methods)

        # 5. A new non-delegation (business logic) method must also be caught,
        #    even if production count alone did not otherwise change (here it
        #    does too, since it's also new -- confirm both metrics fire).
        base_methods.append({"name": "e", "category": "business logic"})
        write_ledger(base_methods)
        current = current_metrics(root, index_rs, ledger_path)
        failures = regressions(current, baseline)
        assert any("syncstate_non_delegation_methods" in f for f in failures), failures
        base_methods.pop()
        write_ledger(base_methods)

        # 6. Growing index.rs's production line count must be caught, while
        #    growing only the #[cfg(test)] section must NOT be caught.
        write_index_rs(11, with_test_block=True)
        current = current_metrics(root, index_rs, ledger_path)
        failures = regressions(current, baseline)
        assert any("index_rs_production_lines" in f for f in failures), failures
        write_index_rs(10, with_test_block=True)
        current = current_metrics(root, index_rs, ledger_path)
        assert regressions(current, baseline) == []

        big_test_block_lines = [f"// production line {i}" for i in range(10)]
        big_test_block_lines += [
            "#[cfg(test)]",
            "mod tests {",
            "    fn a() {}",
            "    fn b() {}",
            "    fn c() {}",
            "    fn d() {}",
            "}",
        ]
        index_rs.write_text("\n".join(big_test_block_lines) + "\n", encoding="utf-8")
        current = current_metrics(root, index_rs, ledger_path)
        assert current["index_rs_production_lines"] == 10, current
        assert regressions(current, baseline) == []
        write_index_rs(10, with_test_block=True)

        # 7. A new Arc<SyncState> holder anywhere under crates/ or daemon/
        #    must be caught.
        (root / "crates" / "somecrate").mkdir(parents=True, exist_ok=True)
        (root / "crates" / "somecrate" / "lib.rs").write_text(
            "struct X { s: std::sync::Arc<SyncState> }\n", encoding="utf-8"
        )
        current = current_metrics(root, index_rs, ledger_path)
        assert current["workspace_arc_syncstate_occurrences"] == 1, current
        failures = regressions(current, baseline)
        assert any("workspace_arc_syncstate_occurrences" in f for f in failures), failures
        (root / "crates" / "somecrate" / "lib.rs").unlink()

        # 8. Shrinking every metric and calling --update-baseline-equivalent
        #    again must lower the recorded baseline.
        base_methods[1]["status"] = "migrated"
        write_ledger(base_methods)
        write_index_rs(8, with_test_block=True)
        current = current_metrics(root, index_rs, ledger_path)
        assert regressions(current, baseline) == []
        write_baseline(baseline_path, current)
        new_baseline = load_baseline(baseline_path)
        assert new_baseline["index_rs_production_lines"] == 8, new_baseline
        assert new_baseline["syncstate_production_methods"] == 1, new_baseline

        # 9. Ledger entry validation: unknown category/status/missing
        #    destination must be caught by ledger_failures.
        bad_methods = [
            {"name": "x", "category": "not-a-real-category"},
        ]
        write_ledger(bad_methods)
        entries = load_ledger(ledger_path)
        failures = ledger_failures(entries)
        assert any("unknown 'category'" in f for f in failures), failures

        # 10. A missing ledger file must raise a hard GateError.
        ledger_path.unlink()
        try:
            load_ledger(ledger_path)
            raise AssertionError("expected GateError for missing ledger")
        except GateError:
            pass

        # 11. A missing baseline file must raise a hard GateError.
        baseline_path.unlink()
        try:
            load_baseline(baseline_path)
            raise AssertionError("expected GateError for missing baseline")
        except GateError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help=(
            "Deliberately ratchet the recorded baseline down to the current "
            "metrics. Only use this after a pass that migrated methods/lines "
            "and re-generated the ledger to match -- never to silently clear "
            "a regression."
        ),
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("phase 7d9f syncstate strangler self-test passed")
        return 0

    try:
        entries = load_ledger(LEDGER_PATH)
    except GateError as exc:
        print(f"phase 7d9f syncstate strangler gate error: {exc}")
        return 1

    failures = ledger_failures(entries)

    try:
        metrics = current_metrics()
    except GateError as exc:
        print(f"phase 7d9f syncstate strangler gate error: {exc}")
        return 1

    print("current metrics:")
    for metric in METRIC_NAMES:
        print(f"  {metric:<40} {metrics[metric]}")

    if args.update_baseline:
        write_baseline(BASELINE_PATH, metrics)
        print(f"baseline updated at {BASELINE_PATH.relative_to(ROOT)}")
        if failures:
            print("phase 7d9f syncstate strangler ledger violations:")
            for failure in failures:
                print(f"- {failure}")
            return 1
        return 0

    try:
        baseline = load_baseline(BASELINE_PATH)
    except GateError as exc:
        print(f"phase 7d9f syncstate strangler gate error: {exc}")
        return 1

    print("baseline:")
    for metric in METRIC_NAMES:
        print(f"  {metric:<40} {baseline[metric]}")

    failures.extend(regressions(metrics, baseline))

    if failures:
        print("phase 7d9f syncstate strangler violations:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Phase 7D-9F SyncState strangler-fig gate passed (no regression)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
