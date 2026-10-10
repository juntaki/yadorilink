#!/usr/bin/env python3
"""Pin how the macOS app chooses between the live and the fixture client.

The fixture client shows made-up folders and only pretends to act, so it must
never be picked implicitly. Rules:

1. `App/ClientFactory.swift`: `FakeYadoriLinkClient` appears only inside the
   `#if DEBUG` branch, only after a check of `YADORILINK_CLIENT == "fake"`;
   the fallthrough returns `makeLiveClient()`. The Release (`#else`) branch
   returns the live client. No `-live`-style opt-out of a fake default.
2. No other file in the app target (`App/`) mentions the fake client.
3. Only the `YadoriLink Fixtures` scheme (project.yml and the checked-in
   xcscheme) sets `YADORILINK_CLIENT=fake`; no other scheme or build setting does.
4. The UI shows the `Fixture` badge when the fake client is active: the main
   window and the menu bar popover use `FixtureBadge`, and `AppContext.isFixture`
   is derived from the client type.

This is a text scan, not a Swift parser (same class as the other
scripts/check-*.py gates).
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAC = Path("platforms/macos/app")
APP = MAC / "YadoriLinkApp/App"
PROJECT_YML = MAC / "YadoriLinkFinderSync/project.yml"
SCHEMES = MAC / "YadoriLinkFinderSync/YadoriLinkFinderSync.xcodeproj/xcshareddata/xcschemes"
VIEWS = MAC / "YadoriLinkApp/Packages/YadoriLinkUI/Sources/YadoriLinkUI/Views"
FIXTURE_SCHEME = "YadoriLink Fixtures"
FAKE_RE = re.compile(r"\bFake(YadoriLinkClient|Scenario)\b")


def read(root: Path, rel: Path) -> str:
    return (root / rel).read_text(encoding="utf-8")


def check_factory(text: str) -> list[str]:
    out: list[str] = []
    if "#if DEBUG" not in text or "#else" not in text:
        return ["ClientFactory.swift must keep its #if DEBUG / #else split"]
    debug, release = text.split("#else", 1)
    debug = debug.split("#if DEBUG", 1)[1]
    release = release.split("#endif", 1)[0]
    head = text.split("#if DEBUG", 1)[0]
    if any(FAKE_RE.search(l) for l in head.splitlines() if not l.strip().startswith("//")):
        out.append("fake client referenced outside the #if DEBUG branch")
    if FAKE_RE.search(release):
        out.append("fake client referenced in the Release (#else) branch")
    if "makeLiveClient()" not in release:
        out.append("Release branch must return makeLiveClient()")
    # The first statement that can return the fake client must be guarded by the explicit env var.
    m = FAKE_RE.search(debug.split("static func fixture(")[0])
    if m:
        before = re.sub(r"return\s*$", "", debug[: m.start()].rstrip())
        if not re.search(r'environment\["YADORILINK_CLIENT"\]\s*==\s*"fake"\s*\{\s*$', before):
            out.append('FakeYadoriLinkClient must be created only under `environment["YADORILINK_CLIENT"] == "fake"`')
        after = debug[m.end():]
        if "makeLiveClient()" not in after:
            out.append("Debug makeClient must fall through to makeLiveClient()")
    else:
        out.append("Debug branch no longer builds the fake client at all; update this check if intended")
    if re.search(r'"-live"|== "live"', text):
        out.append("a live opt-in flag implies a fake default; Debug must be live by default")
    return out


def violations(root: Path) -> list[str]:
    out: list[str] = []
    out += check_factory(read(root, APP / "ClientFactory.swift"))
    for path in sorted((root / APP).rglob("*.swift")):
        rel = path.relative_to(root)
        if path.name == "ClientFactory.swift":
            continue
        code = [l for l in path.read_text(encoding="utf-8").splitlines() if not l.strip().startswith("//")]
        if any(FAKE_RE.search(l) for l in code):
            out.append(f"{rel}: the app target must not reference the fake client outside ClientFactory.swift")

    yml = read(root, PROJECT_YML)
    m = re.search(r"^schemes:\n((?:[ ]+.*\n|\n)+)", yml, re.M)
    block = m.group(1) if m else ""
    if f"{FIXTURE_SCHEME}:" not in block or "YADORILINK_CLIENT: fake" not in block:
        out.append(f"project.yml must define the `{FIXTURE_SCHEME}` scheme setting YADORILINK_CLIENT: fake")
    rest = "\n".join(l for l in yml.replace(block, "").splitlines() if not l.strip().startswith("#"))
    if "YADORILINK_CLIENT" in rest:
        out.append("project.yml: YADORILINK_CLIENT may be set only by the Fixtures scheme")

    for path in sorted((root / SCHEMES).glob("*.xcscheme")):
        sets_fake = re.search(r'key = "YADORILINK_CLIENT"\s+value = "fake"', path.read_text(encoding="utf-8"))
        if path.stem == FIXTURE_SCHEME:
            if not sets_fake:
                out.append(f"{path.name} must set YADORILINK_CLIENT=fake")
        elif sets_fake:
            out.append(f"{path.name}: only the `{FIXTURE_SCHEME}` scheme may select the fake client")
    if not (root / SCHEMES / f"{FIXTURE_SCHEME}.xcscheme").exists():
        out.append(f"missing checked-in scheme {FIXTURE_SCHEME}.xcscheme (regenerate with xcodegen)")

    if "app.client is FakeYadoriLinkClient" not in read(root, VIEWS / "AppContext.swift"):
        out.append("AppContext.isFixture must be derived from `app.client is FakeYadoriLinkClient`")
    for name in ("MainWindowView.swift", "MenuBarContentView.swift"):
        t = read(root, VIEWS / name)
        if "context.isFixture" not in t or "FixtureBadge()" not in t:
            out.append(f"{name} must show FixtureBadge when context.isFixture")
    if "context.isFixture" not in read(root, APP / "YadoriLinkApp.swift"):
        out.append("the menu bar label must mark fixture runs")
    return out


GOOD_FACTORY = '''enum ClientFactory {
    static func makeLiveClient() -> any YadoriLinkClient { LiveYadoriLinkClient() }
}
#if DEBUG
extension ClientFactory {
    static func makeClient(environment: [String: String]) -> any YadoriLinkClient {
        if environment["YADORILINK_CLIENT"] == "fake" {
            return FakeYadoriLinkClient(scenario: fixture())
        }
        return makeLiveClient()
    }
    static func fixture() -> FakeScenario { .healthy }
}
#else
extension ClientFactory {
    static func makeClient() -> any YadoriLinkClient { makeLiveClient() }
}
#endif
'''


def self_test() -> None:
    assert check_factory(GOOD_FACTORY) == [], check_factory(GOOD_FACTORY)
    implicit = GOOD_FACTORY.replace('if environment["YADORILINK_CLIENT"] == "fake" {', "if true {")
    assert check_factory(implicit), "an unconditional fake must be flagged"
    inverted = GOOD_FACTORY.replace("return makeLiveClient()\n    }\n    static", "return FakeYadoriLinkClient(scenario: .healthy)\n    }\n    static")
    assert check_factory(inverted), "a fake fallthrough must be flagged"
    release_fake = GOOD_FACTORY.replace("{ makeLiveClient() }\n}\n#endif", "{ FakeYadoriLinkClient(scenario: .healthy) }\n}\n#endif")
    assert check_factory(release_fake), "a fake in Release must be flagged"
    assert check_factory(GOOD_FACTORY.replace('== "fake"', '== "live"')), "live opt-in must be flagged"
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for rel, text in {
            APP / "ClientFactory.swift": GOOD_FACTORY,
            APP / "Other.swift": "let c = FakeYadoriLinkClient(scenario: .healthy)\n",
        }.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        for rel in (PROJECT_YML,):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("schemes:\n  X:\n    run:\n", encoding="utf-8")
        (root / SCHEMES).mkdir(parents=True)
        (root / SCHEMES / "YadoriLink.xcscheme").write_text('key = "YADORILINK_CLIENT"\n value = "fake"', encoding="utf-8")
        (root / VIEWS).mkdir(parents=True)
        for n in ("AppContext.swift", "MainWindowView.swift", "MenuBarContentView.swift"):
            (root / VIEWS / n).write_text("", encoding="utf-8")
        (root / APP / "YadoriLinkApp.swift").write_text("", encoding="utf-8")
        found = " | ".join(violations(root))
        for needle in ("Other.swift", "only the `YadoriLink Fixtures` scheme", "must define", "isFixture", "FixtureBadge"):
            assert needle in found, (needle, found)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("macos client-selection self-test passed")
        return 0
    failures = violations(ROOT)
    if failures:
        print("macOS client-selection violations:")
        for f in failures:
            print(f"- {f}")
        return 1
    print("macos client-selection check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
