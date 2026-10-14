#!/usr/bin/env python3
"""Fail-fast checks of the provisioning profiles a Developer ID build uses.

  validate-macos-profiles.py profile FILE --bundle-id ID [--print-uuid]
      Decode one .provisionprofile (`security cms -D -i`) and require: the
      team, the exact application identifier, the App Group authorization,
      not expired (or expiring within --min-days), and a Developer ID shape
      (no device list, no get-task-allow).

  validate-macos-profiles.py built-app YadoriLink.app
      Check a built app: each extension embeds a valid profile for its own
      bundle id and its signed App Group is one that profile authorizes; the
      host app embeds no profile and signs no App Group or get-task-allow
      (it claims no restricted entitlement, so a profile for it would be a
      mistake -- or a new entitlement that needs a deliberate profile change).

This is a profile/entitlement contract check, not a signature check: the
signatures, timestamps and exact entitlements of the shipped bytes are verified
by verify-pkg.sh --release.
"""

import argparse
import datetime
import plistlib
import subprocess
import sys
from pathlib import Path

TEAM_ID = "594UQF7QX3"
APP_GROUP = "group.com.juntaki.yadorilink.shared"
HOST_BUNDLE_ID = "com.juntaki.yadorilink"
EXTENSIONS = {
    "YadoriLinkFinderSync.appex": "com.juntaki.yadorilink.FinderSync",
    "YadoriLinkFileProvider.appex": "com.juntaki.yadorilink.FileProvider",
}
GROUPS_KEY = "com.apple.security.application-groups"


class ProfileError(Exception):
    pass


def decode_profile(path: Path) -> dict:
    """The profile's plist, decoded from its CMS envelope by `security`."""
    try:
        proc = subprocess.run(
            ["security", "cms", "-D", "-i", str(path)],
            capture_output=True,
            check=False,
        )
    except OSError as err:
        raise ProfileError(f"{path}: cannot run security: {err}") from err
    if proc.returncode != 0:
        raise ProfileError(f"{path}: security cms could not decode the profile")
    try:
        return plistlib.loads(proc.stdout)
    except Exception as err:  # plistlib raises several types
        raise ProfileError(f"{path}: decoded profile is not a plist") from err


def profile_problems(
    profile: dict,
    bundle_id: str,
    now: datetime.datetime,
    team: str = TEAM_ID,
    group: str = APP_GROUP,
    min_days: float = 1.0,
) -> list:
    problems = []
    ents = profile.get("Entitlements") or {}
    teams = profile.get("TeamIdentifier") or []
    if team not in teams:
        problems.append(f"TeamIdentifier {teams} does not include {team}")
    if ents.get("com.apple.developer.team-identifier", team) != team:
        problems.append(f"team-identifier entitlement is {ents.get('com.apple.developer.team-identifier')}, want {team}")
    app_id = ents.get("com.apple.application-identifier") or ents.get("application-identifier")
    if app_id != f"{team}.{bundle_id}":
        problems.append(f"application identifier is {app_id!r}, want {team + '.' + bundle_id!r}")
    if group not in (ents.get(GROUPS_KEY) or []):
        problems.append(f"App Group {group} is not authorized (have {ents.get(GROUPS_KEY)})")
    if ents.get("com.apple.security.get-task-allow") or ents.get("get-task-allow"):
        problems.append("profile allows get-task-allow (a development profile)")
    if profile.get("ProvisionedDevices"):
        problems.append("profile lists devices (not a Developer ID profile)")
    expires = profile.get("ExpirationDate")
    if not isinstance(expires, datetime.datetime):
        problems.append("profile has no ExpirationDate")
    else:
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=datetime.timezone.utc)
        if expires < now + datetime.timedelta(days=min_days):
            problems.append(f"profile expired or expires within {min_days:g} day(s): {expires.isoformat()}")
    return problems


def describe(profile: dict) -> str:
    expires = profile.get("ExpirationDate")
    return f"uuid={profile.get('UUID')} name={profile.get('Name')!r} expires={expires.isoformat() if expires else None}"


def check_profile_file(path: Path, bundle_id: str, now, min_days: float) -> dict:
    profile = decode_profile(path)
    problems = profile_problems(profile, bundle_id, now, min_days=min_days)
    if problems:
        raise ProfileError(f"{path}: " + "; ".join(problems))
    return profile


def signed_entitlements(item: Path) -> dict:
    proc = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", str(item)],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ProfileError(f"{item}: codesign could not read entitlements")
    if not proc.stdout.strip():
        return {}
    try:
        return plistlib.loads(proc.stdout)
    except Exception as err:
        raise ProfileError(f"{item}: entitlements are not a plist") from err


def check_built_app(app: Path, now, min_days: float) -> list:
    problems = []
    plugins = app / "Contents" / "PlugIns"
    for name, bundle_id in EXTENSIONS.items():
        appex = plugins / name
        embedded = appex / "Contents" / "embedded.provisionprofile"
        if not appex.is_dir():
            problems.append(f"{name} is missing from the app")
            continue
        if not embedded.is_file():
            problems.append(f"{name} embeds no provisioning profile")
            continue
        try:
            profile = check_profile_file(embedded, bundle_id, now, min_days)
            print(f"OK {name}: {describe(profile)}")
            groups = signed_entitlements(appex).get(GROUPS_KEY) or []
            allowed = (profile.get("Entitlements") or {}).get(GROUPS_KEY) or []
            if not groups:
                problems.append(f"{name} signs no App Group")
            for g in groups:
                if g not in allowed:
                    problems.append(f"{name} signs App Group {g} that its profile does not authorize")
        except ProfileError as err:
            problems.append(str(err))
    if (app / "Contents" / "embedded.provisionprofile").exists():
        problems.append("host app embeds a provisioning profile, but it claims no restricted entitlement")
    try:
        ents = signed_entitlements(app)
    except ProfileError as err:
        problems.append(str(err))
        ents = {}
    if ents.get(GROUPS_KEY):
        problems.append(f"host app signs an App Group ({ents[GROUPS_KEY]}); it must hold none")
    if ents.get("com.apple.security.get-task-allow"):
        problems.append("host app signs get-task-allow")
    for appex_name in EXTENSIONS:
        appex = plugins / appex_name
        if appex.is_dir() and signed_entitlements(appex).get("com.apple.security.get-task-allow"):
            problems.append(f"{appex_name} signs get-task-allow")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("profile")
    p.add_argument("file", type=Path)
    p.add_argument("--bundle-id", required=True)
    p.add_argument("--print-uuid", action="store_true", help="print only the UUID on success")
    a = sub.add_parser("built-app")
    a.add_argument("app", type=Path)
    for s in (p, a):
        s.add_argument("--min-days", type=float, default=1.0)
    args = parser.parse_args(argv)
    now = datetime.datetime.now(datetime.timezone.utc)

    try:
        if args.cmd == "profile":
            profile = check_profile_file(args.file, args.bundle_id, now, args.min_days)
            print(profile["UUID"] if args.print_uuid else f"OK {args.bundle_id}: {describe(profile)}")
            return 0
        problems = check_built_app(args.app, now, args.min_days)
    except ProfileError as err:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if not problems:
        print("OK host app: no profile, no App Group, no get-task-allow")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
