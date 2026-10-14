#!/usr/bin/env python3
"""Obtain the two Developer ID provisioning profiles a release build needs.

  ensure-macos-profiles.py ensure --key AuthKey.p8 --key-id ID --issuer ID \\
      --cert-pem CERT.pem --state STATE.json --env-out FILE
  ensure-macos-profiles.py cleanup --state STATE.json

`ensure` uses the App Store Connect API to find the Developer ID Application
certificate that was imported into the build keychain (matched byte for byte,
not "some certificate of the team"), then, for the FinderSync and FileProvider
bundle ids, finds a valid Developer ID (MAC_APP_DIRECT) profile bound to that
certificate or creates one. Each downloaded profile is decoded and checked with
validate-macos-profiles.py's rules, installed under its UUID in Xcode's
provisioning-profile directories, and its path is written to --env-out as
YADORILINK_FINDERSYNC_PROFILE_FILE / YADORILINK_FILEPROVIDER_PROFILE_FILE (the installed
file's path) for build-pkg.sh, which validates the files and derives the UUIDs.

`cleanup` removes exactly the files `ensure` created (listed in --state) and
nothing else; it is safe to run when `ensure` failed or never ran.

Only non-secret metadata is printed: bundle id, profile UUID, name, expiry,
certificate SHA-256 fingerprint. The key, the token and profile contents are
never logged. A 401/403 from the API stops the run with an explanation.
"""

import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("validate_macos_profiles", HERE / "validate-macos-profiles.py")
vmp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vmp)

API_BASE = "https://api.appstoreconnect.apple.com"
CERT_TYPES = "DEVELOPER_ID_APPLICATION,DEVELOPER_ID_APPLICATION_G2"
PROFILE_TYPE = "MAC_APP_DIRECT"
# Environment variable build-pkg.sh reads, per bundle id: the installed profile's path.
TARGETS = (
    ("com.juntaki.yadorilink.FinderSync", "YADORILINK_FINDERSYNC_PROFILE_FILE"),
    ("com.juntaki.yadorilink.FileProvider", "YADORILINK_FILEPROVIDER_PROFILE_FILE"),
)
INSTALL_DIRS = (
    "~/Library/Developer/Xcode/UserData/Provisioning Profiles",
    "~/Library/MobileDevice/Provisioning Profiles",
)


class EnsureError(Exception):
    pass


# --- JWT (ES256) -----------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def der_to_raw_signature(der: bytes) -> bytes:
    """An ECDSA DER signature (SEQUENCE of two INTEGERs) as 32+32 bytes r||s."""
    def read_len(buf, i):
        n = buf[i]
        if n < 0x80:
            return n, i + 1
        k = n & 0x7F
        return int.from_bytes(buf[i + 1 : i + 1 + k], "big"), i + 1 + k

    if not der or der[0] != 0x30:
        raise EnsureError("unexpected signature encoding from openssl")
    _, i = read_len(der, 1)
    parts = []
    for _ in range(2):
        if der[i] != 0x02:
            raise EnsureError("unexpected signature encoding from openssl")
        n, i = read_len(der, i + 1)
        parts.append(int.from_bytes(der[i : i + n], "big").to_bytes(32, "big"))
        i += n
    return parts[0] + parts[1]


def openssl_sign(key_path: str, message: bytes) -> bytes:
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", key_path], input=message, capture_output=True, check=False
    )
    if proc.returncode != 0:
        raise EnsureError("openssl could not sign with the App Store Connect key (is it an ES256 .p8?)")
    return proc.stdout


def make_jwt(key_path: str, key_id: str, issuer: str, now: float = None, sign=openssl_sign) -> str:
    now = int(time.time() if now is None else now)
    header = b64url(json.dumps({"alg": "ES256", "kid": key_id, "typ": "JWT"}, separators=(",", ":")).encode())
    claims = b64url(
        json.dumps(
            {"iss": issuer, "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"}, separators=(",", ":")
        ).encode()
    )
    signing_input = f"{header}.{claims}".encode()
    return f"{header}.{claims}.{b64url(der_to_raw_signature(sign(key_path, signing_input)))}"


# --- HTTP layer ------------------------------------------------------------

class Api:
    """The few App Store Connect calls used, over an injectable transport:
    `transport(method, url, headers, body_bytes) -> (status, body_bytes)`."""

    def __init__(self, base, token, transport=None):
        self.base = base.rstrip("/")
        self.token = token
        self.transport = transport or urllib_transport

    def call(self, method, path, query=None, body=None):
        url = self.base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        try:
            status, raw = self.transport(method, url, headers, data)
        except OSError as err:
            raise EnsureError(f"{method} {path}: network error: {err}") from err
        if status in (401, 403):
            raise EnsureError(self.denied(status, method, path))
        if not 200 <= status < 300:
            raise EnsureError(f"{method} {path}: HTTP {status}: {self.error_summary(raw)}")
        try:
            return json.loads(raw) if raw else {}
        except ValueError as err:
            raise EnsureError(f"{method} {path}: response is not JSON") from err

    @staticmethod
    def error_summary(raw):
        # Only the error codes and titles; never echo a body that could hold profile content.
        try:
            errors = json.loads(raw).get("errors", [])
            return "; ".join(f"{e.get('code')}: {e.get('title')}" for e in errors) or "no error detail"
        except Exception:
            return "unreadable error body"

    @staticmethod
    def denied(status, method, path):
        if status == 401:
            return (
                f"{method} {path}: HTTP 401. The App Store Connect API rejected the token: check "
                "MACOS_NOTARY_KEY_ID, MACOS_NOTARY_KEY_ISSUER_ID/MACOS_NOTARY_ISSUER_ID and that the .p8 "
                "belongs to that key."
            )
        return (
            f"{method} {path}: HTTP 403. This App Store Connect API key may notarize but is not allowed "
            "to manage certificates and provisioning profiles. Use a Team key with the Admin or App "
            "Manager role, or create the two Developer ID profiles by hand and install them "
            "instead of running this step."
        )

    def paged(self, path, query):
        query = dict(query, limit="200")
        out = {"data": [], "included": []}
        while True:
            page = self.call("GET", path, query)
            out["data"] += page.get("data", [])
            out["included"] += page.get("included", [])
            nxt = (page.get("links") or {}).get("next")
            if not nxt:
                return out
            parsed = urllib.parse.urlparse(nxt)
            query = dict(urllib.parse.parse_qsl(parsed.query))


def urllib_transport(method, url, headers, data):
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60, context=ssl.create_default_context()) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


# --- certificate and profile resolution ------------------------------------

def local_cert_der(pem_path: Path) -> bytes:
    try:
        return ssl.PEM_cert_to_DER_cert(pem_path.read_text())
    except Exception as err:
        raise EnsureError(f"{pem_path}: not a PEM certificate") from err


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def find_certificate(api: Api, der: bytes) -> str:
    certs = api.paged("/v1/certificates", {"filter[certificateType]": CERT_TYPES})["data"]
    for cert in certs:
        content = (cert.get("attributes") or {}).get("certificateContent")
        if content and base64.b64decode(content) == der:
            return cert["id"]
    raise EnsureError(
        f"The imported Developer ID Application certificate (sha256 {fingerprint(der)}) is not among the "
        f"team's {len(certs)} Developer ID Application certificates in App Store Connect. The P12 secret may hold a "
        "revoked or foreign certificate."
    )


def find_bundle(api: Api, identifier: str) -> str:
    rows = api.paged("/v1/bundleIds", {"filter[identifier]": identifier})["data"]
    exact = [r for r in rows if (r.get("attributes") or {}).get("identifier") == identifier]
    if not exact:
        raise EnsureError(f"Bundle id {identifier} is not registered for this team in App Store Connect.")
    bundle_id = exact[0]["id"]
    caps = api.paged(f"/v1/bundleIds/{bundle_id}/bundleIdCapabilities", {})["data"]
    if not any((c.get("attributes") or {}).get("capabilityType") == "APP_GROUPS" for c in caps):
        raise EnsureError(f"Bundle id {identifier} does not have the App Groups capability enabled.")
    return bundle_id


def candidate_profiles(api: Api, bundle_id: str, cert_id: str) -> list:
    # GET /v1/profiles is the endpoint that supports filters and `include`; the
    # relationship linkage (which bundle id, which certificates) is present for
    # the included resources. The downloaded profile is verified again below.
    page = api.paged(
        "/v1/profiles",
        {"filter[profileType]": PROFILE_TYPE, "filter[profileState]": "ACTIVE", "include": "bundleId,certificates"},
    )
    found = []
    for prof in page["data"]:
        attrs = prof.get("attributes") or {}
        rels = prof.get("relationships") or {}
        linked = {c["id"] for c in (rels.get("certificates") or {}).get("data") or []}
        bundle = ((rels.get("bundleId") or {}).get("data") or {}).get("id")
        if attrs.get("profileType") != PROFILE_TYPE or attrs.get("profileState") != "ACTIVE":
            continue
        if bundle != bundle_id or cert_id not in linked:
            continue
        if not attrs.get("profileContent") or not attrs.get("expirationDate"):
            continue
        found.append(prof)
    return sorted(found, key=lambda p: p["attributes"]["expirationDate"], reverse=True)


def create_profile(api: Api, bundle_id: str, cert_id: str, identifier: str, now) -> dict:
    suffix = identifier.rsplit(".", 1)[-1]
    body = {
        "data": {
            "type": "profiles",
            "attributes": {"name": f"yadorilink {suffix} Developer ID {now:%Y%m%d%H%M%S}", "profileType": PROFILE_TYPE},
            "relationships": {
                "bundleId": {"data": {"type": "bundleIds", "id": bundle_id}},
                "certificates": {"data": [{"type": "certificates", "id": cert_id}]},
            },
        }
    }
    return api.call("POST", "/v1/profiles", body=body)["data"]


def check_downloaded(prof: dict, identifier: str, der: bytes, now, scratch: Path):
    """(raw bytes, problems): the profile content decoded and held to the
    validator's rules, plus the requirement that it embeds our certificate."""
    raw = base64.b64decode(prof["attributes"]["profileContent"])
    tmp = scratch / "candidate.provisionprofile"
    tmp.write_bytes(raw)
    decoded = vmp.decode_profile(tmp)
    problems = vmp.profile_problems(decoded, identifier, now)
    if der not in [bytes(c) for c in decoded.get("DeveloperCertificates", [])]:
        problems.append("profile does not contain the imported Developer ID Application certificate")
    return raw, decoded, problems


def install(raw: bytes, uuid: str, dirs: list, created: list) -> str:
    """Write <uuid>.provisionprofile into each dir, recording each file in
    `created` before it is written (so a write that fails part way is still
    cleaned up). A file that already exists is never replaced and never
    recorded. Returns the path in the first directory."""
    for d in dirs:
        target = Path(d).expanduser() / f"{uuid}.provisionprofile"
        if target.exists():
            if target.read_bytes() != raw:
                raise EnsureError(f"{target} already exists with different content; refusing to overwrite it")
            continue  # identical and not ours: leave it, and never remove it
        target.parent.mkdir(parents=True, exist_ok=True)
        created.append(str(target))
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            created.pop()  # lost a race to someone else's file: not ours
            raise EnsureError(f"{target} appeared while installing; refusing to overwrite it")
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
    return str(Path(dirs[0]).expanduser() / f"{uuid}.provisionprofile")


def write_state(path: Path, files: list):
    path.write_text(json.dumps({"files": files}))


def cmd_ensure(args, api: Api, now) -> int:
    der = local_cert_der(Path(args.cert_pem))
    state_path = Path(args.state)
    files = []
    write_state(state_path, files)  # present from the start, so cleanup always has a state to read
    env_lines = []
    cert_id = find_certificate(api, der)
    print(f"certificate: sha256 {fingerprint(der)} matched in App Store Connect")
    with tempfile.TemporaryDirectory(prefix="ensure-profiles-") as scratch:
        for identifier, env_name in TARGETS:
            bundle_id = find_bundle(api, identifier)
            chosen = None
            for prof in candidate_profiles(api, bundle_id, cert_id):
                raw, decoded, problems = check_downloaded(prof, identifier, der, now, Path(scratch))
                if not problems:
                    chosen, action = (raw, decoded), "reused"
                    break
                print(f"{identifier}: skipping profile {prof['attributes'].get('name')!r}: {'; '.join(problems)}")
            if chosen is None:
                created = create_profile(api, bundle_id, cert_id, identifier, now)
                raw, decoded, problems = check_downloaded(created, identifier, der, now, Path(scratch))
                if problems:
                    raise EnsureError(f"{identifier}: the newly created profile is unusable: " + "; ".join(problems))
                chosen, action = (raw, decoded), "created"
            raw, decoded = chosen
            try:
                path = install(raw, decoded["UUID"], args.install_dir or list(INSTALL_DIRS), files)
            finally:
                write_state(state_path, files)
            print(f"{identifier}: {action} profile {vmp.describe(decoded)}")
            env_lines.append(f"{env_name}={path}")
    Path(args.env_out).write_text("\n".join(env_lines) + "\n")
    return 0


def cmd_cleanup(args) -> int:
    try:
        files = json.loads(Path(args.state).read_text()).get("files", [])
    except (OSError, ValueError):
        return 0  # ensure never ran, or died before writing its state: nothing was installed
    for f in files:
        Path(f).unlink(missing_ok=True)
        print(f"removed {Path(f).name}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("ensure")
    e.add_argument("--key", required=True)
    e.add_argument("--key-id", required=True)
    e.add_argument("--issuer", required=True)
    e.add_argument("--cert-pem", required=True)
    e.add_argument("--state", required=True)
    e.add_argument("--env-out", required=True)
    e.add_argument("--api-base", default=os.environ.get("YADORILINK_ASC_API_BASE", API_BASE))
    e.add_argument("--install-dir", action="append", help="override the install directories (repeatable)")
    c = sub.add_parser("cleanup")
    c.add_argument("--state", required=True)
    args = parser.parse_args(argv)
    if args.cmd == "cleanup":
        return cmd_cleanup(args)
    try:
        api = Api(args.api_base, make_jwt(args.key, args.key_id, args.issuer))
        return cmd_ensure(args, api, datetime.datetime.now(datetime.timezone.utc))
    except (EnsureError, vmp.ProfileError) as err:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
