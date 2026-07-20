#!/usr/bin/env python3
"""Generate, validate, and sign the per-channel update manifest that
`automatic-updates` clients consume.

The manifest schema is defined by the daemon client, not here — see
`crates/yadorilink-daemon/src/update/manifest.rs` (`UpdateManifest` /
`ReleaseEntry` / `SignedManifestEnvelope`). Signing reuses the maintainer
tool `yadorilink-sign-manifest` (same crate) so the signed bytes are exactly
what the client's `verify_and_parse` accepts: an Ed25519 signature over the
literal manifest body bytes, carried in an envelope alongside the key id.

Two subcommands:

  generate  Build a fresh channel manifest from an artifacts spec (used by the
            release/nightly pipeline once artifacts are built + signed).

  resign    Take an already-published signed manifest, change ONLY the
            operator-controlled fields (rollout percentage, kill-switch,
            minimum supported version) on its entries, and re-sign — leaving
            the referenced artifacts untouched. This is the
            rollout/kill-switch/min-version operator path: no artifact rebuild.

Signing is gated on the key being present: with MANIFEST_SIGNING_KEY set the
output is a signed envelope; without it the tool writes the unsigned body and
exits non-zero for `generate --require-signature` (release), or warns and
writes the body for local/dry runs.

Artifacts spec (generate --artifacts FILE), JSON:
  [
    {"platform":"macos","arch":"aarch64","install_source":"standalone",
     "artifact_url":"https://.../yadorilink-macos.pkg",
     "artifact_sha256":"<64 hex>", "artifact_publisher_identity":"Developer ID Installer: ..."},
    ...
  ]
The shared fields (channel, version, minimum_supported_version,
rollout_percentage, kill_switch, mandatory, release_notes_url) are applied to
every entry.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_SCHEMA_VERSION = 1
CHANNELS = ("nightly", "beta")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Fields the client requires with no serde default — must always be present.
REQUIRED_ENTRY_FIELDS = (
    "channel",
    "platform",
    "arch",
    "install_source",
    "version",
    "minimum_supported_version",
    "artifact_url",
    "artifact_sha256",
)


def parse_semver(raw: str) -> tuple[int, int, int, str]:
    """Match the client's tolerant-of-leading-v strict semver parse
    (crates/.../manifest.rs parse_semver). Returns a comparable tuple; the
    prerelease string is compared lexically only for equal core versions,
    which is enough for the min<=version validation we do here."""
    s = raw[1:] if raw.startswith("v") else raw
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$", s)
    if not m:
        raise ValueError(f"not strict semver: {raw!r}")
    pre = s[m.end(3):]
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre)


def version_le(a: str, b: str) -> bool:
    """a <= b on the semver core (prerelease ignored for the min-version
    gate, which only needs 'minimum not above published core version')."""
    ca = parse_semver(a)[:3]
    cb = parse_semver(b)[:3]
    return ca <= cb


def build_manifest(shared: dict, artifacts: list[dict], generated_at: str) -> dict:
    releases = []
    for a in artifacts:
        entry = {
            "channel": shared["channel"],
            "platform": a["platform"],
            "arch": a["arch"],
            "install_source": a["install_source"],
            "version": shared["version"],
            "minimum_supported_version": shared["minimum_supported_version"],
            "rollout_percentage": int(shared["rollout_percentage"]),
            "kill_switch": bool(shared["kill_switch"]),
            "mandatory": bool(shared["mandatory"]),
            "artifact_url": a["artifact_url"],
            "artifact_sha256": a["artifact_sha256"].lower(),
            "artifact_publisher_identity": a.get("artifact_publisher_identity", ""),
            "release_notes_url": shared.get("release_notes_url", ""),
        }
        releases.append(entry)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_at": generated_at,
        "releases": releases,
    }


def validate_manifest(manifest: dict, check_urls: bool) -> list[str]:
    """Field/consistency validation that must pass BEFORE signing
    (spec: 'Manifest is validated before signing'). Returns a list of
    problems; empty means valid."""
    problems: list[str] = []
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        problems.append(
            f"schema_version must be {MANIFEST_SCHEMA_VERSION}, got {manifest.get('schema_version')!r}"
        )
    releases = manifest.get("releases")
    if not isinstance(releases, list) or not releases:
        problems.append("releases must be a non-empty array")
        return problems

    for i, e in enumerate(releases):
        where = f"releases[{i}]"
        for f in REQUIRED_ENTRY_FIELDS:
            if not e.get(f):
                problems.append(f"{where}.{f} is required and non-empty")
        ch = e.get("channel")
        if ch not in CHANNELS:
            problems.append(f"{where}.channel {ch!r} is not one of {CHANNELS}")
        roll = e.get("rollout_percentage", 0)
        if not isinstance(roll, int) or not (0 <= roll <= 100):
            problems.append(f"{where}.rollout_percentage {roll!r} must be an int in 0..100")
        sha = e.get("artifact_sha256", "")
        if not SHA256_RE.match(sha):
            problems.append(f"{where}.artifact_sha256 must be 64 lowercase hex chars")
        ver = e.get("version", "")
        minv = e.get("minimum_supported_version", "")
        try:
            if ver and minv and not version_le(minv, ver):
                problems.append(
                    f"{where}.minimum_supported_version {minv} exceeds version {ver}"
                )
        except ValueError as ex:
            problems.append(f"{where}: {ex}")
        if check_urls:
            url = e.get("artifact_url", "")
            if not _url_resolves(url, sha):
                problems.append(f"{where}.artifact_url does not resolve (or checksum sidecar missing): {url}")
    return problems


def _url_resolves(url: str, sha256: str) -> bool:
    """Best-effort reachability + checksum-sidecar check. Only run under
    --check-urls (network); kept out of the default path so the tool is
    testable offline."""
    import urllib.request

    def head_ok(u: str) -> bool:
        try:
            req = urllib.request.Request(u, method="HEAD")
            with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
                return 200 <= r.status < 400
        except Exception:
            return False

    if not head_ok(url):
        return False
    # The repo's release convention publishes a `<artifact>.sha256` sidecar;
    # confirm it exists and matches when reachable.
    try:
        with urllib.request.urlopen(url + ".sha256", timeout=20) as r:  # noqa: S310
            sidecar = r.read().decode().split()[0].strip().lower()
            if SHA256_RE.match(sidecar):
                return sidecar == sha256.lower()
    except Exception:
        pass
    return True  # sidecar unavailable is not fatal; HEAD already passed


def sign_or_write(manifest: dict, out_path: Path, *, require_signature: bool,
                  sign_tool: str, key_id: str) -> int:
    """Write the manifest body and, if MANIFEST_SIGNING_KEY is set, sign it
    into a `SignedManifestEnvelope` via `yadorilink-sign-manifest`. The signer
    reads the body bytes verbatim, so the signature covers exactly what the
    client re-reads."""
    body_json = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"

    key = os.environ.get("MANIFEST_SIGNING_KEY", "").strip()
    if not key:
        msg = "MANIFEST_SIGNING_KEY is not set; cannot sign the manifest."
        if require_signature:
            print(f"error: {msg}", file=sys.stderr)
            return 3
        print(f"warning: {msg} Writing UNSIGNED body to {out_path}.", file=sys.stderr)
        out_path.write_text(body_json, encoding="utf-8")
        return 0

    with tempfile.TemporaryDirectory() as td:
        body_file = Path(td) / "manifest-body.json"
        body_file.write_text(body_json, encoding="utf-8")
        cmd = [
            sign_tool, "sign",
            "--key-hex", key,
            "--key-id", key_id,
            "--manifest", str(body_file),
            "--out", str(out_path),
        ]
        # Never echo the key. Pass it as an argv element (already avoided in
        # logs by not printing cmd verbatim).
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        except FileNotFoundError:
            print(
                f"error: signer not found: {sign_tool}. Build it first, e.g.\n"
                f"  cargo build --release -p yadorilink-daemon --bin yadorilink-sign-manifest",
                file=sys.stderr,
            )
            return 4
        except subprocess.CalledProcessError as ex:
            print(f"error: yadorilink-sign-manifest failed (exit {ex.returncode})", file=sys.stderr)
            return ex.returncode
    print(f"wrote signed manifest envelope to {out_path} (key_id={key_id})")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    artifacts = json.loads(Path(args.artifacts).read_text(encoding="utf-8"))
    if not isinstance(artifacts, list) or not artifacts:
        print("error: --artifacts must be a non-empty JSON array", file=sys.stderr)
        return 2
    if args.channel not in CHANNELS:
        print(f"error: --channel must be one of {CHANNELS}", file=sys.stderr)
        return 2

    generated_at = args.generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    shared = {
        "channel": args.channel,
        "version": args.version,
        "minimum_supported_version": args.min_version,
        "rollout_percentage": args.rollout_percentage,
        "kill_switch": args.kill_switch,
        "mandatory": args.mandatory,
        "release_notes_url": args.release_notes_url,
    }
    manifest = build_manifest(shared, artifacts, generated_at)

    problems = validate_manifest(manifest, check_urls=args.check_urls)
    if problems:
        print("manifest validation failed:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 5

    return sign_or_write(
        manifest, Path(args.out),
        require_signature=args.require_signature,
        sign_tool=args.sign_tool, key_id=args.key_id,
    )


def cmd_resign(args: argparse.Namespace) -> int:
    """Operator control path: mutate rollout / kill-switch / min-version on an
    existing published manifest and re-sign, preserving artifact refs."""
    envelope_or_body = json.loads(Path(args.input).read_text(encoding="utf-8"))
    # Accept either a signed envelope (has manifest_json) or a raw body.
    if isinstance(envelope_or_body, dict) and "manifest_json" in envelope_or_body:
        manifest = json.loads(envelope_or_body["manifest_json"])
    else:
        manifest = envelope_or_body

    for e in manifest.get("releases", []):
        if args.rollout_percentage is not None:
            e["rollout_percentage"] = int(args.rollout_percentage)
        if args.kill_switch is not None:
            e["kill_switch"] = bool(args.kill_switch)
        if args.min_version is not None:
            e["minimum_supported_version"] = args.min_version
    # Refresh the generation timestamp so consumers can see the change.
    manifest["generated_at"] = args.generated_at or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    problems = validate_manifest(manifest, check_urls=False)
    if problems:
        print("re-signed manifest validation failed:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 5

    return sign_or_write(
        manifest, Path(args.out),
        require_signature=args.require_signature,
        sign_tool=args.sign_tool, key_id=args.key_id,
    )


def _add_common_signing_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--out", required=True, help="output path for the signed envelope")
    p.add_argument("--sign-tool", default=os.environ.get("YADORILINK_SIGN_MANIFEST", "yadorilink-sign-manifest"),
                   help="path to the yadorilink-sign-manifest binary")
    p.add_argument("--key-id", default=os.environ.get("MANIFEST_SIGNING_KEY_ID", "yadorilink-beta-dev-2026"),
                   help="key id; MUST match a manifest::TRUSTED_KEYS entry in the shipped client")
    p.add_argument("--require-signature", action="store_true",
                   help="fail (non-zero) instead of writing an unsigned body when the key is absent")
    p.add_argument("--generated-at", default=None, help="RFC3339 timestamp; defaults to now (UTC)")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="build + validate + sign a fresh channel manifest")
    g.add_argument("--channel", required=True, choices=CHANNELS)
    g.add_argument("--version", required=True)
    g.add_argument("--min-version", required=True, dest="min_version")
    g.add_argument("--artifacts", required=True, help="JSON file of per-platform artifact entries")
    g.add_argument("--rollout-percentage", type=int, default=100)
    g.add_argument("--kill-switch", action="store_true")
    g.add_argument("--mandatory", action="store_true")
    g.add_argument("--release-notes-url", default="")
    g.add_argument("--check-urls", action="store_true", help="HEAD each artifact_url (+ .sha256) before signing")
    _add_common_signing_args(g)
    g.set_defaults(func=cmd_generate)

    r = sub.add_parser("resign", help="operator: change rollout/kill-switch/min-version and re-sign")
    r.add_argument("--input", required=True, help="existing signed envelope or manifest body")
    r.add_argument("--rollout-percentage", type=int, default=None)
    kill = r.add_mutually_exclusive_group()
    kill.add_argument("--kill-switch", dest="kill_switch", action="store_const", const=True, default=None)
    kill.add_argument("--clear-kill-switch", dest="kill_switch", action="store_const", const=False)
    r.add_argument("--min-version", default=None, dest="min_version")
    _add_common_signing_args(r)
    r.set_defaults(func=cmd_resign)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
