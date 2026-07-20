#!/usr/bin/env python3
"""Validate durability invariants and their executable test references."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "docs/design/data-durability-model.md"
BETA_GATE = ROOT / "docs/BETA_RELEASE_GATE.md"


def main() -> int:
    model = MODEL.read_text(encoding="utf-8")
    failures: list[str] = []
    rust_files = {
        path: path.read_text(encoding="utf-8") for path in (ROOT / "crates").rglob("*.rs")
    }
    for number in range(1, 8):
        if f"## DL-{number}:" not in model:
            failures.append(f"missing DL-{number}")
    for field in (
        "Target state:",
        "Destructive operations:",
        "Enforcement symbol:",
        "Test IDs:",
        "Runtime diagnosis:",
    ):
        if model.count(field) != 7:
            failures.append(f"expected 7 occurrences of {field!r}")

    test_lines = "\n".join(line for line in model.splitlines() if line.startswith("- Test IDs:"))
    test_ids = re.findall(r"`([a-z][a-z0-9_]+)`", test_lines)
    for test_id in test_ids:
        definitions = []
        pattern = re.compile(rf"\bfn\s+{re.escape(test_id)}\s*\(")
        for path, source in rust_files.items():
            for match in pattern.finditer(source):
                definitions.append((path, source[max(0, match.start() - 300) : match.start()]))
        if not definitions:
            failures.append(f"documented test does not exist: {test_id}")
            continue
        if len(definitions) > 1:
            failures.append(f"documented test ID is ambiguous: {test_id}")
        for path, prefix in definitions:
            attributes = prefix.split("fn ")[-1]
            if not re.search(r"#\s*\[(?:tokio::)?test(?:\([^]]*\))?\]", attributes):
                failures.append(f"documented test is not an executable test: {test_id} ({path})")
            if re.search(r"#\s*\[ignore(?:\s*=.*)?\]", attributes):
                failures.append(f"documented durability test must not be ignored: {test_id}")

    if "design/data-durability-model.md" not in BETA_GATE.read_text(encoding="utf-8"):
        failures.append("BETA_RELEASE_GATE.md does not reference the durability model")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(f"data durability model: ok ({len(test_ids)} test references)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
