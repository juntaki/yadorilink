#!/usr/bin/env python3
"""Overlays architecture/dependency-rules.toml verdicts onto the generated
crate graph and module coupling graphs, producing one combined DOT graph
color-coded by rule verdict.

Usage:
    scripts/gen-dependency-boundary-graph.py \
        architecture/dependency-rules.toml \
        architecture/graphs/generated/workspace-crates.dot \
        architecture/graphs/generated/yadorilink-daemon-coupling.dot \
        architecture/graphs/generated/yadorilink-sync-core-coupling.dot \
        > architecture/graphs/generated/dependency-boundaries.dot

Colors:
    blue   = matches an `allow` rule
    red    = matches a `deny` rule
    yellow = matches a `known_violation` rule
    gray   = matches no rule (unclassified)
"""
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    import tomli as tomllib

EDGE_RE = re.compile(r'^\s*"([^"]+)"\s*->\s*"([^"]+)"')

COLORS = {
    "deny": "#cc3333",
    "allow": "#3366cc",
    "known_violation": "#d4a017",
    "unclassified": "#999999",
}


def load_edges(dot_path: Path, namespace: str | None) -> list[tuple[str, str]]:
    edges = []
    for line in dot_path.read_text(encoding="utf-8").splitlines():
        m = EDGE_RE.match(line)
        if not m:
            continue
        src, dst = m.group(1), m.group(2)
        if namespace:
            src = f"{namespace}::{src}" if not src.startswith(namespace) else src
            dst = f"{namespace}::{dst}" if not dst.startswith(namespace) else dst
        edges.append((src, dst))
    return edges


def classify(rules: list[dict], src: str, dst: str) -> str:
    for rule in rules:
        frm = rule["from"]
        if src != frm and not src.startswith(frm + "::"):
            continue
        for kind in ("deny", "allow", "known_violation"):
            for prefix in rule.get(kind, []):
                if dst == prefix or dst.startswith(prefix + "::"):
                    return kind
    return "unclassified"


def main() -> int:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <rules.toml> <dot-file>...", file=sys.stderr)
        return 1

    rules_path = Path(sys.argv[1])
    dot_paths = [Path(p) for p in sys.argv[2:]]

    rules = tomllib.loads(rules_path.read_text(encoding="utf-8"))["rule"]

    edges: list[tuple[str, str]] = []
    for dot_path in dot_paths:
        stem = dot_path.stem
        namespace = None
        if stem.endswith("-coupling"):
            namespace = stem[: -len("-coupling")]
        edges.extend(load_edges(dot_path, namespace))
    edges = sorted(set(edges))

    nodes = sorted({n for e in edges for n in e})

    print("digraph dependency_boundaries {")
    print('    label="dependency boundary overlay (see architecture/dependency-rules.toml)";')
    print('    labelloc="t";')
    print('    rankdir="LR";')
    print('    node [shape=box, fontname="Helvetica"];')
    print('    edge [fontname="Helvetica", fontsize=10];')

    for node in nodes:
        print(f'    "{node}";')

    for src, dst in edges:
        verdict = classify(rules, src, dst)
        color = COLORS[verdict]
        print(f'    "{src}" -> "{dst}" [color="{color}", label="{verdict}", fontcolor="{color}"];')

    print("}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
