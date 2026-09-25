#!/usr/bin/env python3
"""Re-verify a published signed update manifest as a CI gate
(spec: 'Add a CI gate that re-verifies each published manifest's signature and
internal consistency').

This performs the SAME checks the daemon client does, independently of the
private signing key:
  1. Ed25519 signature over the exact `manifest_json` bytes verifies under the
     pinned trust-root public key for the envelope's `key_id`.
  2. The body parses and passes field/consistency validation.
  3. With --artifacts-dir, every entry's artifact exists there under the file
     name in its artifact_url, and its byte count and SHA-256 equal the
     entry's artifact_size and artifact_sha256.

The key to verify against is always explicit: --key-id with --public-key-hex
(the release key for a release manifest), or --dev-trust-root for the
development key compiled into non-release builds. There is no default, so a
release manifest can never be checked against the development key by
omission.

Requires the `cryptography` package for Ed25519 verification.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

# Mirror of the development TRUSTED_KEYS in manifest.rs (public half only),
# used only with --dev-trust-root.
DEV_TRUSTED_KEYS = {
    "yadorilink-beta-dev-2026": "00e033f866c263139ff4afd165e75bae3cfca67eb32399dddd6e33a3251af1e3",
}


def _load_validator():
    """Reuse validate_manifest from the sibling generator (hyphenated filename,
    so load it via importlib)."""
    path = Path(__file__).with_name("generate-update-manifest.py")
    spec = importlib.util.spec_from_file_location("gen_update_manifest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.validate_manifest


def verify(envelope_json: str, trusted: dict[str, str]) -> list[str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    problems: list[str] = []
    try:
        env = json.loads(envelope_json)
    except json.JSONDecodeError as e:
        return [f"envelope is not valid JSON: {e}"]

    key_id = env.get("key_id")
    manifest_json = env.get("manifest_json")
    sig_b64 = env.get("signature_base64")
    if not (isinstance(key_id, str) and isinstance(manifest_json, str) and isinstance(sig_b64, str)):
        return ["envelope missing key_id / manifest_json / signature_base64"]

    pub_hex = trusted.get(key_id)
    if pub_hex is None:
        return [f"unknown signing key id: {key_id!r} (not in trust root)"]

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        sig = base64.b64decode(sig_b64)
        pub.verify(sig, manifest_json.encode("utf-8"))
    except InvalidSignature:
        return ["signature verification FAILED"]
    except Exception as e:  # malformed key/sig encoding
        return [f"signature could not be checked: {e}"]

    # Signature good — now internal consistency of the signed body.
    try:
        manifest = json.loads(manifest_json)
    except json.JSONDecodeError as e:
        return [f"signed manifest body is not valid JSON: {e}"]
    validate_manifest = _load_validator()
    problems.extend(validate_manifest(manifest, check_urls=False))
    return problems


def check_artifacts(envelope_json: str, artifacts_dir: Path) -> list[str]:
    """Compare each entry's artifact_size and artifact_sha256 with the file of
    the same name in artifacts_dir (the bytes that are about to be published)."""
    manifest = json.loads(json.loads(envelope_json)["manifest_json"])
    problems: list[str] = []
    for i, e in enumerate(manifest.get("releases", [])):
        where = f"releases[{i}]"
        name = str(e.get("artifact_url", "")).rsplit("/", 1)[-1]
        path = artifacts_dir / name
        if not name or not path.is_file():
            problems.append(f"{where}: artifact {name!r} not found in {artifacts_dir}")
            continue
        data = path.read_bytes()
        if e.get("artifact_size") != len(data):
            problems.append(
                f"{where}.artifact_size {e.get('artifact_size')!r} != {len(data)} bytes in {path}"
            )
        digest = hashlib.sha256(data).hexdigest()
        if e.get("artifact_sha256") != digest:
            problems.append(f"{where}.artifact_sha256 does not match {path} ({digest})")
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("envelope", help="path to the signed manifest envelope JSON")
    ap.add_argument("--public-key-hex", default=None, help="hex Ed25519 public key to verify against")
    ap.add_argument("--key-id", default=None, help="key id for --public-key-hex")
    ap.add_argument("--dev-trust-root", action="store_true",
                    help="verify against the development key instead (never for a release manifest)")
    ap.add_argument("--artifacts-dir", default=None,
                    help="directory holding the artifacts; check their size and SHA-256 against the manifest")
    args = ap.parse_args(argv)

    if args.dev_trust_root:
        if args.public_key_hex or args.key_id:
            print("error: --dev-trust-root cannot be combined with --key-id/--public-key-hex", file=sys.stderr)
            return 2
        trusted = DEV_TRUSTED_KEYS
    elif args.public_key_hex and args.key_id:
        trusted = {args.key_id: args.public_key_hex}
    else:
        print("error: pass --key-id and --public-key-hex (or --dev-trust-root)", file=sys.stderr)
        return 2

    envelope_json = Path(args.envelope).read_text(encoding="utf-8")
    problems = verify(envelope_json, trusted)
    if not problems and args.artifacts_dir:
        problems = check_artifacts(envelope_json, Path(args.artifacts_dir))
    if problems:
        print(f"manifest verification FAILED for {args.envelope}:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"manifest verified OK: {args.envelope}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
