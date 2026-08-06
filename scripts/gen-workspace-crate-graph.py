#!/usr/bin/env python3
"""Generates a DOT graph of workspace-member-to-workspace-member
dependencies only (no external crates), from `cargo metadata`.

Usage:
    scripts/gen-workspace-crate-graph.py > architecture/graphs/generated/workspace-crates.dot
    dot -Tsvg architecture/graphs/generated/workspace-crates.dot -o architecture/graphs/generated/workspace-crates.svg

This is deliberately a plain compile-time dependency graph (which workspace
crate depends on which), not a module-level or runtime-flow graph -- see
`cargo modules dependencies` for module-level graphs within one crate, and
hand-drawn sequence diagrams for runtime flows (channels, spawned tasks,
persistence) that a static dependency graph cannot represent.

Edge style:
    solid  = normal (production) dependency
    dashed = dev-dependency
    dotted = build-dependency or optional/cfg-gated dependency

Output is sorted (packages, then their dependencies) so the same source
tree always produces the same DOT text, and the commit SHA is embedded in
the graph label instead of a timestamp so re-generating from an unchanged
tree never creates a diff.
"""
import json
import subprocess
import sys


def edge_style(dep: dict) -> str:
    if dep.get("kind") == "dev":
        return "dashed"
    if dep.get("kind") == "build" or dep.get("optional"):
        return "dotted"
    return "solid"


def git_sha() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() or "unknown"


def main() -> int:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        capture_output=True,
        text=True,
        check=True,
    )
    metadata = json.loads(result.stdout)
    packages = sorted(metadata["packages"], key=lambda pkg: pkg["name"])
    member_names = {pkg["name"] for pkg in packages}

    print("digraph workspace_crates {")
    print(f'    label="workspace-crates @ {git_sha()}";')
    print('    labelloc="t";')
    print('    rankdir="LR";')
    print('    node [shape=box, fontname="Helvetica"];')

    for pkg in packages:
        name = pkg["name"]
        print(f'    "{name}";')

    edges = []
    for pkg in packages:
        name = pkg["name"]
        for dep in pkg.get("dependencies", []):
            dep_name = dep["name"]
            if dep_name not in member_names or dep_name == name:
                continue
            edges.append((name, dep_name, edge_style(dep)))

    for name, dep_name, style in sorted(set(edges)):
        print(f'    "{name}" -> "{dep_name}" [style={style}];')

    print("}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
