#!/usr/bin/env python3
"""Pin every production namespace mutation that is not a durable namespace step.

A change to a name that the product's correctness rests on (a published file, a
created or removed directory, a removed file whose absence is then recorded) goes
through `yadorilink_root_authority::durable_dir`: a write-through move on Windows,
a rename or unlink plus a sync of the directories on Unix. Anything else that
calls a raw rename, unlink, hard link or move, a Windows `MoveFileExW`,
`FlushFileBuffers` or placeholder-creating API is a name the product does not
claim is durable. Those are allowed only where losing the change is harmless,
and they are listed here, file by file with a count, so a new one fails until it
is reviewed.

`ALLOWLIST` is that review: every entry says why losing (or not completing) the
change cannot break an invariant. `PENDING` lists the sites that do not yet go
through `durable_dir` although the Windows design says they must; the guard
refuses a build in which the Windows gate constant is `true` while it is not
empty, so the gate cannot be opened over unfinished work.

Production code is what `check-materialization-semantic-boundary.py` scans
(`crates/*/src`) plus the Windows shell crate's `src`. Run with no arguments to
check the tree, `--list` to print every counted site, `--self-test` to exercise
the check against synthetic fixtures.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "materialization_semantic_boundary",
    Path(__file__).resolve().parent / "check-materialization-semantic-boundary.py",
)
_boundary = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_boundary)

NAMES = (
    "fs::rename",
    "fs::remove_file",
    "fs::remove_dir",
    "fs::remove_dir_all",
    "fs::hard_link",
    "MoveFileExW",
    "FlushFileBuffers",
    "DeleteFileW",
    "RemoveDirectoryW",
    "CreateHardLinkW",
    "CfCreatePlaceholders",
    "CfConvertToPlaceholder",
)
PATTERN = _boundary.call_pattern(NAMES)
SHELL_GLOB = "platforms/windows/shell/src/**/*.rs"
GATE_FILE = "crates/yadorilink-root-authority/src/durable_dir.rs"
GATE = re.compile(r"WINDOWS_DIRECTORY_DURABILITY_VALIDATED\s*:\s*bool\s*=\s*(true|false)")

C = "crates/"
S = "platforms/windows/shell/src/"

ALLOWLIST: dict[str, dict[str, int]] = {
    # The durable steps themselves, and the throwaway artefacts of the probes.
    C + "yadorilink-root-authority/src/durable_dir.rs": {
        "fs::hard_link": 1,
        "fs::remove_dir": 2,
        "fs::remove_file": 4,
        "fs::rename": 1,
    },
    C + "yadorilink-root-authority/src/durable_dir/raw.rs": {"MoveFileExW": 1, "fs::rename": 1},
    C + "yadorilink-root-authority/src/durable_dir/probe.rs": {"fs::remove_dir_all": 2},
    C + "yadorilink-root-authority/src/fs_capabilities.rs": {"fs::remove_file": 20, "fs::rename": 1},
    C + "yadorilink-peer-session/src/hazard.rs": {"fs::remove_dir_all": 1},
    # The local-storage seam: the removal and replace primitives behind the
    # durable operations, and the plain Windows rename a writer falls back to on
    # a volume with no durable move.
    C + "yadorilink-local-storage/src/fs_ops.rs": {
        "fs::remove_dir": 1,
        "fs::remove_file": 1,
        "fs::rename": 1,
    },
    C + "yadorilink-local-storage/src/materialize_write.rs": {"MoveFileExW": 1},
    # The cleanup of a writer's own temporary file after a failed write: the
    # temporary name is the writer's, nothing refers to it, and a leftover is
    # harmless.
    C + "yadorilink-client-core/src/coordination/device_config.rs": {"fs::remove_file": 2},
    C + "yadorilink-client-core/src/ops/provider_pending.rs": {"fs::remove_file": 1},
    C + "yadorilink-daemon/src/author_sidecar.rs": {"fs::remove_file": 1},
    C + "yadorilink-fapi-client/src/store/file.rs": {"fs::remove_file": 2},
    C + "yadorilink-reporting/src/local_store/consent_store.rs": {"fs::remove_file": 1},
    C + "yadorilink-sqlite-runtime/src/creation_marker.rs": {"fs::remove_file": 1},
    C + "yadorilink-transport/src/key_secret_store.rs": {"fs::remove_file": 2},
    C + "yadorilink-daemon/src/hydration.rs": {"fs::remove_file": 1},
    # The recovery area and item store are private product state; what a restart
    # removes there is removed by a record or by being the area's own Stage
    # file, and the area itself leaves by a durable move.
    C + "yadorilink-sync-sqlite/src/native_rebootstrap_recovery.rs": {
        "fs::remove_dir": 1,
        "fs::remove_file": 3,
    },
    # Startup recovery of the temp-file ledger: it removes what a record names.
    C + "yadorilink-daemon/src/replica_coordinator/materialization_owner/repair.rs": {
        "fs::remove_dir": 1,
        "fs::remove_file": 1,
    },
    # The quarantined object of a rebootstrap removal: the move that quarantined
    # it is the durable step; unlinking it is not.
    C + "yadorilink-daemon/src/native_rebootstrap.rs": {"fs::remove_file": 1},
    # Unix-only eviction: its own quarantine with a barrier after each step; the
    # native Windows provider never reaches it.
    C + "yadorilink-filesystem-sync/src/materialization_eviction.rs": {
        "fs::hard_link": 1,
        "fs::remove_file": 2,
    },
    # Configuration, logs, counters and caches whose loss or reversion
    # costs nothing that a restart does not redo.
    C + "yadorilink-daemon/src/governance_config.rs": {"fs::rename": 1},
    C + "yadorilink-daemon/src/log_roll.rs": {"fs::rename": 1},
    C + "yadorilink-daemon/src/reporting/counters.rs": {"fs::rename": 1},
    C + "yadorilink-daemon/src/update/policy.rs": {"fs::rename": 1},
    C + "yadorilink-reporting/src/local_store/entry_store.rs": {"fs::remove_file": 1, "fs::rename": 2},
    C + "yadorilink-reporting/src/local_store/error_candidates.rs": {"fs::remove_file": 1},
    C + "yadorilink-reporting/src/metrics_config.rs": {"fs::rename": 1},
    C + "yadorilink-desktop-app/src/login_item.rs": {"fs::remove_file": 1},
    C + "yadorilink-desktop-app/src/window.rs": {"fs::remove_file": 2},
    C + "yadorilink-daemon/src/app.rs": {"fs::remove_file": 1},
    C + "yadorilink-daemon/src/control_socket.rs": {"fs::remove_file": 1},
    C + "yadorilink-daemon/src/shell_ipc.rs": {"fs::remove_file": 1},
    # Provider state that is rebuilt on start or re-derived from the daemon: the
    # handoff directory is emptied at every start on Windows, and a removed copy
    # whose replacement was published durably is only garbage.
    C + "yadorilink-daemon/src/provider_handoff.rs": {"fs::remove_dir_all": 1, "fs::remove_file": 1},
    C + "yadorilink-daemon/src/shell_ipc/provider_apply.rs": {"fs::remove_file": 7},
    C + "yadorilink-daemon/src/shell_ipc/provider_materialize.rs": {"fs::remove_file": 5},
    # The Windows shell crate: the cleanup of its own temporary and ingest copies,
    # the host's unregistration, and an old placeholder that is removed so it
    # can be recreated (a rerun redoes it).
    S + "bin/cfapi_host.rs": {"fs::remove_file": 1},
    S + "cfapi.rs": {"fs::remove_file": 1},
    S + "provider_authoring.rs": {"fs::remove_file": 5},
    S + "provider_namespace.rs": {
        "CfConvertToPlaceholder": 1,
        "fs::remove_dir": 1,
        "fs::remove_file": 1,
    },
}

# Sites the Windows design says must be durable steps and are not yet. Empty
# before the gate may be opened.
PENDING: dict[str, dict[str, int]] = {
    # A placeholder is created by an API with no write-through flag. Creating it
    # under a Stage name and moving it needs the placeholder state to survive a
    # rename inside the sync root, which has to be shown on a Windows host first;
    # until then `save_shown` and the acknowledgement that follow it have nothing
    # durable to stand on.
    S + "cfapi.rs": {"CfCreatePlaceholders": 1},
}


def scan(root: Path) -> list[tuple[str, int, str, str]]:
    hits = list(_boundary.scan(root, PATTERN))
    shell = sorted(root.glob(SHELL_GLOB))
    tests = _boundary.test_module_files(shell)
    for path in shell:
        if path.resolve() in tests:
            continue
        rel = str(path.relative_to(root))
        enclosing = "<module>"
        for number, code in _boundary.production_lines(path, path.read_text(encoding="utf-8")):
            name = _boundary.FN_NAME.match(code)
            if name:
                enclosing = name.group(1)
            for match in PATTERN.finditer(code):
                if re.search(r"\bfn\s+$", code[: match.start()]):
                    continue
                hits.append((rel, number, enclosing, match.group(1)))
    return hits


def evaluate(
    hits: list[tuple[str, int, str, str]],
    allowlist: dict[str, dict[str, int]],
    pending: dict[str, dict[str, int]],
) -> list[str]:
    errors: list[str] = []
    found: Counter = Counter()
    where: dict[tuple[str, str], list[int]] = {}
    for rel, number, _, api in hits:
        key = (rel, api)
        found[key] += 1
        where.setdefault(key, []).append(number)
    expected: dict[tuple[str, str], int] = {}
    for table in (allowlist, pending):
        for rel, apis in table.items():
            for api, count in apis.items():
                expected[(rel, api)] = expected.get((rel, api), 0) + count
    for key in sorted(set(found) | set(expected)):
        rel, api = key
        if found[key] == expected.get(key, 0):
            continue
        lines = ", ".join(str(n) for n in where.get(key, [])) or "none"
        if key not in expected:
            errors.append(
                f"{rel}:{lines}: `{api}` is not a durable namespace step and is not reviewed; "
                "use `yadorilink_root_authority::durable_dir`, or add the site to ALLOWLIST "
                "with the reason losing it is harmless"
            )
        else:
            errors.append(f"{rel}: `{api}` pinned at {expected[key]}, found {found[key]} (lines: {lines})")
    return errors


def gate_errors(root: Path, pending: dict[str, dict[str, int]]) -> list[str]:
    text = (root / GATE_FILE).read_text(encoding="utf-8") if (root / GATE_FILE).is_file() else ""
    match = GATE.search(text)
    if match is None:
        return [f"{GATE_FILE}: the Windows gate constant was not found"]
    if match.group(1) == "true" and pending:
        sites = ", ".join(sorted(pending))
        return [f"the Windows gate is open while sites are still pending in: {sites}"]
    return []


def self_test() -> None:
    hit = ("crates/demo/src/lib.rs", 3, "f", "fs::rename")
    assert evaluate([hit], {}, {}) and "not reviewed" in evaluate([hit], {}, {})[0]
    assert evaluate([hit], {"crates/demo/src/lib.rs": {"fs::rename": 1}}, {}) == []
    stale = evaluate([hit], {"crates/demo/src/lib.rs": {"fs::rename": 2}}, {})
    assert stale and "pinned at 2, found 1" in stale[0], stale
    assert evaluate([], {"crates/demo/src/lib.rs": {"fs::rename": 1}}, {}) != []
    pending = {"crates/demo/src/lib.rs": {"fs::rename": 1}}
    assert evaluate([hit], {}, pending) == []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        gate = root / GATE_FILE
        gate.parent.mkdir(parents=True)
        gate.write_text("pub(crate) const WINDOWS_DIRECTORY_DURABILITY_VALIDATED: bool = false;\n")
        assert gate_errors(root, pending) == []
        gate.write_text("pub(crate) const WINDOWS_DIRECTORY_DURABILITY_VALIDATED: bool = true;\n")
        assert gate_errors(root, {}) == []
        assert gate_errors(root, pending), "an open gate over pending work must fail"
        src = root / "crates/demo/src"
        src.mkdir(parents=True)
        (src / "lib.rs").write_text("fn f() { std::fs::rename(a, b); MoveFileExW(x); }\n", encoding="utf-8")
        found = [(h[0], h[3]) for h in scan(root)]
        assert ("crates/demo/src/lib.rs", "fs::rename") in found, found
        assert ("crates/demo/src/lib.rs", "MoveFileExW") in found, found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--list", action="store_true", help="print every counted site")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("durable namespace guard self-test passed")
        return 0
    hits = scan(ROOT)
    if args.list:
        for rel, number, enclosing, api in hits:
            print(f"{rel}:{number}\t{enclosing}\t{api}")
        return 0
    errors = evaluate(hits, ALLOWLIST, PENDING) + gate_errors(ROOT, PENDING)
    if errors:
        print("durable namespace steps must stay on the reviewed sites:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    pending = sum(sum(apis.values()) for apis in PENDING.values())
    total = sum(sum(apis.values()) for apis in ALLOWLIST.values())
    print(f"durable namespace guard: ok ({total} reviewed sites, {pending} pending)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
