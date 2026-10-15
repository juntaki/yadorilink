#!/usr/bin/env python3
"""Every PE file the Windows installer ships must be in the sign list.

platforms/windows/package/shipped-binaries.txt is the one list that
sign-payload.ps1 signs and verify-installer.ps1 checks. This guard fails
when yadorilink.iss packs a PE file (.exe/.dll/.sys/.ocx) that is not in
that list or from the wrong source dir, or when a listed file is not packed.
It also fails when build-installer.ps1 stops handing Inno Setup the signed
staging directory. Run with --self-test to exercise the comparison.
"""

import re
import sys
from pathlib import Path

PKG = Path("platforms/windows/package")
PE = re.compile(r"\.(exe|dll|sys|ocx)$", re.I)
SRC = re.compile(r'^Source:\s*"([^"]+)"', re.I | re.M)


def listed(text: str) -> set[tuple[str, str]]:
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            src, name = line.split()
            out.add((src, name))
    return out


def packed(iss: str) -> set[tuple[str, str]]:
    out = set()
    for path in SRC.findall(iss):
        name = re.split(r"[\\/]", path)[-1]
        if not PE.search(name):
            continue
        if path.startswith("{#BinDir}"):
            out.add(("bin", name))
        elif path.startswith("{#ShellExtDir}"):
            out.add(("shell", name))
        else:
            out.add(("other:" + path, name))
    return out


def problems(list_text: str, iss: str, build: str) -> list[str]:
    want, have = listed(list_text), packed(iss)
    errs = [f"shipped but not in shipped-binaries.txt: {s} {n}" for s, n in sorted(have - want)]
    errs += [f"in shipped-binaries.txt but not packed: {s} {n}" for s, n in sorted(want - have)]
    for needle in ('"/DBinDir=$payloadDir"', '"/DShellExtDir=$payloadDir"', "sign-payload.ps1"):
        if needle not in build:
            errs.append(f"build-installer.ps1 no longer uses the signed staging dir ({needle})")
    return errs


def self_test() -> None:
    lst = "bin a.exe\nshell b.dll\n"
    iss = 'Source: "{#BinDir}\\a.exe"\nSource: "{#ShellExtDir}\\b.dll"\nSource: "x.ps1"\n'
    build = '"/DBinDir=$payloadDir" "/DShellExtDir=$payloadDir" sign-payload.ps1'
    assert not problems(lst, iss, build)
    assert problems(lst, iss + 'Source: "{#BinDir}\\new.exe"\n', build)
    assert problems(lst + "bin c.exe\n", iss, build)
    assert problems(lst, iss, "sign-payload.ps1")
    print("self-test ok")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0
    errs = problems(
        (PKG / "shipped-binaries.txt").read_text(),
        (PKG / "yadorilink.iss").read_text(),
        (PKG / "build-installer.ps1").read_text(),
    )
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
