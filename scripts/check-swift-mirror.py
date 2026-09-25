#!/usr/bin/env python3
"""Keeps the macOS app's Swift mirror types in step with the generated binding.

The app's views and view models build and test without Rust, against
hand-written mirror types (`YadoriLinkModel/Types.swift`) that must match the
Swift UniFFI generates from the client layer: the same type names, the same
fields in the same order, the same enum cases with the same associated-value
labels and types. The live client converts between the two field for field.

Modes:

  check-swift-mirror.py [GENERATED_DIR]
      Compares the generated product types with the mirror and fails on any
      difference. GENERATED_DIR defaults to the checked-in binding.

  check-swift-mirror.py --emit-mapping GENERATED_DIR
      Prints the app's FFIMapping.swift: one `init(_:)` per type in each
      direction, field for field, with no logic.

Generated error enums spell their cases in UpperCamelCase (`NotSignedIn`);
the mirror uses Swift's usual lowerCamelCase (`notSignedIn`). That is the only
spelling difference allowed.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = REPO_ROOT / "shell-ext/macos/YadoriLinkApp"
DEFAULT_GENERATED = APP_DIR / "FFI/Generated"
MIRROR = APP_DIR / "Packages/YadoriLinkUI/Sources/YadoriLinkModel/Types.swift"

# The generated file holding the product types (the client layer's crate).
PRODUCT_TYPES_FILE = "YadoriLinkCore.swift"


@dataclass
class Case:
    name: str
    values: list[tuple[str, str]]  # (label, type)


@dataclass
class SwiftType:
    name: str
    kind: str  # "struct" | "enum"
    fields: list[tuple[str, str]] = field(default_factory=list)
    cases: list[Case] = field(default_factory=list)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def split_top_level(text: str, sep: str = ",") -> list[str]:
    parts, depth, current = [], 0, []
    for ch in text:
        if ch in "([<":
            depth += 1
        elif ch in ")]>":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def body_after(text: str, start: int) -> tuple[str, int]:
    """The text inside the braces opening at or after `start`."""
    open_at = text.index("{", start)
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at + 1 : i], i
    raise ValueError("unbalanced braces")


def depth_one_statements(body: str) -> str:
    """The parts of a type body outside any nested braces."""
    out, depth = [], 0
    for ch in body:
        if ch == "{":
            depth += 1
            continue
        if ch == "}":
            depth -= 1
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def normalize_type(t: str) -> str:
    return re.sub(r"\s+", "", t)


def statements(flat: str) -> list[str]:
    """Newline-separated statements, keeping a parenthesized list that spans
    lines (a generated case's associated values) or a case list continued
    after a trailing comma in one statement."""
    out, depth, current = [], 0, []
    for ch in flat:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "\n" and depth == 0 and not "".join(current).rstrip().endswith(","):
            out.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    out.append("".join(current).strip())
    return [s for s in out if s]


def parse_cases(body: str) -> list[Case]:
    cases = []
    for statement in statements(depth_one_statements(body)):
        if not statement.startswith("case "):
            continue
        for item in split_top_level(statement[len("case ") :]):
            name_match = re.match(r"`?(\w+)`?\s*(\((.*)\))?\s*$", item, flags=re.S)
            if not name_match:
                raise ValueError(f"cannot parse enum case {item!r}")
            values = []
            if name_match.group(3) is not None:
                for value in split_top_level(name_match.group(3)):
                    label, _, typ = value.partition(":")
                    values.append((label.strip(), normalize_type(typ)))
            cases.append(Case(name_match.group(1), values))
    return cases


def parse_fields(body: str) -> list[tuple[str, str]]:
    flat = depth_one_statements(body)
    return [
        (m.group(1), normalize_type(m.group(2)))
        for m in re.finditer(r"public\s+(?:var|let)\s+(\w+)\s*:\s*([^\n=]+)", flat)
    ]


def parse_types(text: str) -> dict[str, SwiftType]:
    text = strip_comments(text)
    types: dict[str, SwiftType] = {}
    pattern = re.compile(r"\bpublic\s+(struct|enum)\s+(\w+)\b[^{]*\{", flags=re.S)
    for match in pattern.finditer(text):
        kind, name = match.group(1), match.group(2)
        if name.startswith(("FfiConverter", "Uniffi")):
            continue
        body, _ = body_after(text, match.start())
        swift_type = SwiftType(name, kind)
        if kind == "struct":
            swift_type.fields = parse_fields(body)
        else:
            swift_type.cases = parse_cases(body)
        types[name] = swift_type
    return types


def lower_first(name: str) -> str:
    return name[:1].lower() + name[1:]


def generated_types(generated_dir: Path) -> dict[str, SwiftType]:
    types = parse_types((generated_dir / PRODUCT_TYPES_FILE).read_text())
    for swift_type in types.values():
        for case in swift_type.cases:
            case.name = lower_first(case.name)
    return types


def mirror_types() -> dict[str, SwiftType]:
    return parse_types(MIRROR.read_text())


def compare(generated: dict[str, SwiftType], mirror: dict[str, SwiftType]) -> list[str]:
    problems = []
    for name in sorted(set(generated) - set(mirror)):
        problems.append(f"{name}: generated, but missing from the mirror")
    for name in sorted(set(mirror) - set(generated)):
        problems.append(f"{name}: in the mirror, but not generated")
    for name in sorted(set(generated) & set(mirror)):
        g, m = generated[name], mirror[name]
        if g.kind != m.kind:
            problems.append(f"{name}: generated as a {g.kind}, mirrored as a {m.kind}")
        elif g.kind == "struct" and g.fields != m.fields:
            problems.append(f"{name}: fields differ\n  generated {g.fields}\n  mirror    {m.fields}")
        elif g.kind == "enum":
            g_cases = [(c.name, c.values) for c in g.cases]
            m_cases = [(c.name, c.values) for c in m.cases]
            if g_cases != m_cases:
                problems.append(f"{name}: cases differ\n  generated {g_cases}\n  mirror    {m_cases}")
    return problems


# ---- FFIMapping.swift -------------------------------------------------------------


def convert(expr: str, typ: str, target: str, known: set[str]) -> str:
    if typ in known:
        return f"{target}.{typ}({expr})"
    optional = re.fullmatch(r"(\w+)\?", typ)
    if optional and optional.group(1) in known:
        return f"{expr}.map {{ {target}.{optional.group(1)}($0) }}"
    array = re.fullmatch(r"\[(\w+)\]", typ)
    if array and array.group(1) in known:
        return f"{expr}.map {{ {target}.{array.group(1)}($0) }}"
    dictionary = re.fullmatch(r"\[String:(\w+)\]", typ)
    if dictionary and dictionary.group(1) in known:
        return f"{expr}.mapValues {{ {target}.{dictionary.group(1)}($0) }}"
    if any(name in re.findall(r"\w+", typ) for name in known):
        raise ValueError(f"no conversion written for {typ!r}")
    return expr


def case_name(name: str, module: str, error_enum: bool) -> str:
    """How a case is spelled in `module`: generated error cases are UpperCamel."""
    if module == "YadoriLinkFFI" and error_enum:
        return name[:1].upper() + name[1:]
    return name


def emit_init(t: SwiftType, source: str, target: str, known: set[str], error_enums: set[str]) -> str:
    lines = [f"extension {target}.{t.name} {{", f"    init(_ value: {source}.{t.name}) {{"]
    if t.kind == "struct":
        args = ", ".join(
            f"{label}: {convert('value.' + label, typ, target, known)}" for label, typ in t.fields
        )
        lines.append(f"        self.init({args})")
    else:
        is_error = t.name in error_enums
        lines.append("        switch value {")
        for case in t.cases:
            src = case_name(case.name, source, is_error)
            dst = case_name(case.name, target, is_error)
            if not case.values:
                lines.append(f"        case .{src}: self = .{dst}")
                continue
            bound = ", ".join(label for label, _ in case.values)
            args = ", ".join(
                f"{label}: {convert(label, typ, target, known)}" for label, typ in case.values
            )
            lines.append(f"        case let .{src}({bound}): self = .{dst}({args})")
        lines.append("        }")
    lines += ["    }", "}", ""]
    return "\n".join(lines)


def emit_mapping(generated_dir: Path) -> str:
    raw = (generated_dir / PRODUCT_TYPES_FILE).read_text()
    error_enums = set(re.findall(r"\benum\s+(\w+)\s*:\s*Swift\.Error", strip_comments(raw)))
    types = generated_types(generated_dir)
    known = set(types)
    out = [
        "// Generated by scripts/generate-swift-bindings.sh (scripts/check-swift-mirror.py).",
        "// Do not edit. One field-for-field conversion per product type, in each",
        "// direction, between the generated binding (YadoriLinkFFI) and the app's",
        "// mirror types (YadoriLinkModel).",
        "",
        "import Foundation",
        "import YadoriLinkFFI",
        "import YadoriLinkModel",
        "",
    ]
    for name in sorted(types):
        out.append(emit_init(types[name], "YadoriLinkFFI", "YadoriLinkModel", known, error_enums))
    for name in sorted(types):
        out.append(emit_init(types[name], "YadoriLinkModel", "YadoriLinkFFI", known, error_enums))
    return "\n".join(out).rstrip() + "\n"


def main(argv: list[str]) -> int:
    if argv[:1] == ["--emit-mapping"]:
        sys.stdout.write(emit_mapping(Path(argv[1])))
        return 0
    generated_dir = Path(argv[0]) if argv else DEFAULT_GENERATED
    generated = generated_types(generated_dir)
    mirror = mirror_types()
    problems = compare(generated, mirror)
    if problems:
        print("check-swift-mirror: the Swift mirror types differ from the generated binding:")
        for problem in problems:
            print(f"- {problem}")
        print(f"Update {MIRROR.relative_to(REPO_ROOT)} to match.")
        return 1
    print(f"check-swift-mirror: {len(generated)} product types match the generated binding")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
