#!/usr/bin/env python3
"""Fail-fast checks of the provisioning profiles a Developer ID build uses.

  validate-macos-profiles.py profile FILE --bundle-id ID [--print-uuid]
      Decode one .provisionprofile (`security cms -D -i`) and require: the
      team, the exact application identifier, the App Group authorization,
      not expired (or expiring within --min-days), and a Developer ID shape
      (no device list, no get-task-allow).

  validate-macos-profiles.py built-app YadoriLink.app
      Check a built app: all three signed bundles (the host app and the
      FinderSync and File Provider extensions) each embed a valid profile for
      their own bundle id, sign at least one App Group, every signed App Group
      is one that bundle's profile authorizes, and none signs get-task-allow.
      Since the host claims application-groups (App.entitlements) it needs a
      profile like the extensions do.

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
# Every signed bundle that carries the App Group: name -> (bundle id, path of
# the bundle inside the app, path of its embedded profile inside the bundle).
TARGETS = {
    "YadoriLink.app": (HOST_BUNDLE_ID, "", "Contents/embedded.provisionprofile"),
    "YadoriLinkFinderSync.appex": (
        "com.juntaki.yadorilink.FinderSync",
        "Contents/PlugIns/YadoriLinkFinderSync.appex",
        "Contents/embedded.provisionprofile",
    ),
    "YadoriLinkFileProvider.appex": (
        "com.juntaki.yadorilink.FileProvider",
        "Contents/PlugIns/YadoriLinkFileProvider.appex",
        "Contents/embedded.provisionprofile",
    ),
}
APP_ID_KEYS = ("com.apple.application-identifier", "application-identifier")
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


def bundle_identifier(bundle: Path) -> str:
    try:
        return plistlib.loads((bundle / "Contents" / "Info.plist").read_bytes()).get("CFBundleIdentifier") or ""
    except Exception:
        return ""


def check_target(name: str, bundle: Path, embedded: Path, bundle_id: str, now, min_days: float) -> list:
    """Problems of one signed bundle: its embedded profile is valid for its
    own bundle id, and the signed entitlements fit inside that profile."""
    if not bundle.is_dir():
        return [f"{name} is missing from the app"]
    if not embedded.is_file():
        return [f"{name} embeds no provisioning profile"]
    actual = bundle_identifier(bundle)
    if actual != bundle_id:
        return [f"{name} has CFBundleIdentifier {actual!r}, want {bundle_id!r}"]
    try:
        profile = check_profile_file(embedded, bundle_id, now, min_days)
        print(f"OK {name}: {describe(profile)}")
        signed = signed_entitlements(bundle)
    except ProfileError as err:
        return [str(err)]
    problems = []
    pents = profile.get("Entitlements") or {}
    allowed = pents.get(GROUPS_KEY) or []
    groups = signed.get(GROUPS_KEY) or []
    if not groups:
        problems.append(f"{name} signs no App Group")
    for g in groups:
        if g not in allowed:
            problems.append(f"{name} signs App Group {g} that its profile does not authorize")
    for key in APP_ID_KEYS:
        want = pents.get("com.apple.application-identifier") or pents.get("application-identifier")
        if key in signed and signed[key] != want:
            problems.append(f"{name} signs application identifier {signed[key]!r}, its profile has {want!r}")
    if signed.get("com.apple.security.get-task-allow"):
        problems.append(f"{name} signs get-task-allow")
    return problems


def check_built_app(app: Path, now, min_days: float) -> list:
    problems = []
    for name, (bundle_id, bundle_rel, profile_rel) in TARGETS.items():
        bundle = app / bundle_rel if bundle_rel else app
        problems += check_target(name, bundle, bundle / profile_rel, bundle_id, now, min_days)
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
        print("OK: host app and both extensions carry a valid profile that authorizes their signed App Group")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
