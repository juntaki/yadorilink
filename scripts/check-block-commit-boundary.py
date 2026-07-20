#!/usr/bin/env python3
"""Keep final block publication/removal behind FsBlockStore's commit backend."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "crates/yadorilink-local-storage/src/fs_backend.rs"
LOCAL_STORAGE_SRC = ROOT / "crates/yadorilink-local-storage/src"


def production_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    return text.split("\n#[cfg(test)]\nmod tests", 1)[0]


def locations(pattern: str, text: str) -> list[int]:
    compiled = re.compile(pattern)
    return [index for index, line in enumerate(text.splitlines(), 1) if compiled.search(line)]


def main() -> int:
    backend = production_text(BACKEND)
    violations: list[str] = []

    expected_counts = {
        r"\bfs::hard_link\(": (1, "atomic no-replace publish primitive"),
        r"\bfs::remove_file\(": (1, "physical removal primitive"),
        r"\bfs::rename\(": (1, "corrupt-block quarantine relocation primitive"),
        r"\.commit_block\(": (1, "commit_block caller"),
        r"\bfile\.sync_all\(": (1, "temp-file durability sync"),
        r"fs::File::open\(path\)\?\.sync_all\(": (1, "Unix directory durability sync"),
        r"\bCreateFileW\(": (1, "Windows directory handle open"),
        r"\bFlushFileBuffers\(": (1, "Windows directory durability flush"),
    }
    for pattern, (expected, label) in expected_counts.items():
        found = locations(pattern, backend)
        if len(found) != expected:
            violations.append(
                f"{BACKEND.relative_to(ROOT)}: expected {expected} {label}, "
                f"found {len(found)} at lines {found}"
            )

    # Other local-storage modules may delegate through BlockStore, but must
    # never acquire a second raw filesystem publication/removal primitive.
    raw_mutation = re.compile(r"\b(?:std::)?fs::(?:hard_link|rename|remove_file)\(")
    for path in LOCAL_STORAGE_SRC.rglob("*.rs"):
        if path == BACKEND:
            continue
        for line_number, line in enumerate(production_text(path).splitlines(), 1):
            if raw_mutation.search(line):
                violations.append(
                    f"{path.relative_to(ROOT)}:{line_number}: raw block mutation outside fs_backend"
                )

    if violations:
        print("block commit boundary violated", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    print("block commit boundary: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
