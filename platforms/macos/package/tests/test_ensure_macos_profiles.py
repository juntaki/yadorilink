"""Tests of ensure-macos-profiles.py against a fake App Store Connect API.

The script runs as a subprocess, pointed at an in-process HTTP server that
verifies the ES256 token with openssl, models certificates, bundle ids and
profiles, and records every request. `security` is the same plain-plist fake
the validator tests use, so profile "content" in the fake API is a plist.

Run: python3 -m unittest discover -s platforms/macos/package/tests
"""

import base64
import datetime
import json
import os
import plistlib
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "ensure-macos-profiles.py"
sys.path.insert(0, str(HERE))
import test_validate_macos_profiles as tv  # noqa: E402  (shares the profile builder and fake security)

vmp = tv.vmp
KEY_ID, ISSUER = "ABC123DEFG", "11111111-2222-3333-4444-555555555555"
HOST, FINDER, PROVIDER = tv.HOST, tv.FINDER, tv.PROVIDER
CERT_DER = b"synthetic-developer-id-certificate-der"
OTHER_DER = b"a-different-certificate"


def pem(der: bytes) -> str:
    return ssl.DER_cert_to_PEM_cert(der)


def raw_to_der(raw: bytes) -> bytes:
    def integer(b):
        b = b.lstrip(b"\0") or b"\0"
        if b[0] & 0x80:
            b = b"\0" + b
        return b"\x02" + bytes([len(b)]) + b
    body = integer(raw[:32]) + integer(raw[32:])
    return b"\x30" + bytes([len(body)]) + body


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


BUNDLE_IDS = {HOST: "B-host", FINDER: "B-finder", PROVIDER: "B-provider"}


def profile_resource(rid, bundle, cert_ids, *, ptype="MAC_APP_DIRECT", state="ACTIVE", ders=(CERT_DER,), **over):
    plist = tv.make_profile(bundle, UUID=f"UUID-{rid}", ExpirationDate=tv.NOW + datetime.timedelta(days=900), **over)
    plist["DeveloperCertificates"] = list(ders)
    # The script compares against the real clock; make fixtures valid for years.
    plist["ExpirationDate"] = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=300)
    return {
        "type": "profiles",
        "id": rid,
        "attributes": {
            "name": f"existing {rid}",
            "profileType": ptype,
            "profileState": state,
            "expirationDate": plist["ExpirationDate"].isoformat(),
            "profileContent": base64.b64encode(plistlib.dumps(plist)).decode(),
        },
        "relationships": {
            "certificates": {"data": [{"type": "certificates", "id": c} for c in cert_ids]},
            "bundleId": {"data": {"type": "bundleIds", "id": BUNDLE_IDS[bundle]}},
        },
    }


class FakeAsc:
    """State and request handling for the fake API."""

    def __init__(self, pubkey_pem: Path):
        self.pubkey = pubkey_pem
        self.requests = []
        self.force_status = None
        self.certs = [
            {"type": "certificates", "id": "C-other", "attributes": {"certificateType": "DEVELOPER_ID_APPLICATION", "certificateContent": base64.b64encode(OTHER_DER).decode()}},
            {"type": "certificates", "id": "C-ours", "attributes": {"certificateType": "DEVELOPER_ID_APPLICATION", "certificateContent": base64.b64encode(CERT_DER).decode()}},
        ]
        self.bundles = {
            HOST: {"id": "B-host", "caps": ["APP_GROUPS"]},
            FINDER: {"id": "B-finder", "caps": ["APP_GROUPS"]},
            PROVIDER: {"id": "B-provider", "caps": ["APP_GROUPS"]},
        }
        self.profiles = []
        self.created = 0

    def verify_jwt(self, header):
        auth = header or ""
        if not auth.startswith("Bearer "):
            return False
        h, c, sig = auth[7:].split(".")
        head, claims = json.loads(b64url_decode(h)), json.loads(b64url_decode(c))
        ok = head == {"alg": "ES256", "kid": KEY_ID, "typ": "JWT"}
        ok = ok and claims["iss"] == ISSUER and claims["aud"] == "appstoreconnect-v1"
        ok = ok and 0 < claims["exp"] - claims["iat"] <= 1200
        raw = b64url_decode(sig)
        ok = ok and len(raw) == 64
        if not ok:
            return False
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as d:
            sigfile = Path(d, "sig")
            sigfile.write_bytes(raw_to_der(raw))
            proc = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(self.pubkey), "-signature", str(sigfile)],
                input=f"{h}.{c}".encode(), capture_output=True,
            )
        return proc.returncode == 0

    def handle(self, method, path, query, body, auth):
        self.requests.append((method, path, auth))
        if not self.verify_jwt(auth):
            return 401, {"errors": [{"code": "NOT_AUTHORIZED", "title": "bad token"}]}
        if self.force_status:
            return self.force_status, {"errors": [{"code": "FORBIDDEN_ERROR", "title": "no access"}]}
        if method == "GET" and path == "/v1/certificates":
            cursor = int(query.get("cursor", ["0"])[0])
            wanted = query["filter[certificateType]"][0].split(",")
            assert set(wanted) <= {"DEVELOPER_ID_APPLICATION", "DEVELOPER_ID_APPLICATION_G2"}, wanted
            data = [c for c in self.certs if c["attributes"]["certificateType"] in wanted]
            page = {"data": data[cursor : cursor + 1]}
            if cursor + 1 < len(data):
                page["links"] = {"next": f"http://x/v1/certificates?cursor={cursor + 1}&limit=200&filter[certificateType]={query['filter[certificateType]'][0]}"}
            return 200, page
        if method == "GET" and path == "/v1/bundleIds":
            ident = query["filter[identifier]"][0]
            # the real filter is a prefix-ish match: also return a near miss
            rows = [{"type": "bundleIds", "id": b["id"], "attributes": {"identifier": i}} for i, b in self.bundles.items() if i.startswith(ident)]
            rows.append({"type": "bundleIds", "id": "B-decoy", "attributes": {"identifier": ident + ".extra"}})
            return 200, {"data": rows}
        for ident, b in self.bundles.items():
            if path == f"/v1/bundleIds/{b['id']}/bundleIdCapabilities":
                return 200, {"data": [{"type": "bundleIdCapabilities", "attributes": {"capabilityType": c}} for c in b["caps"]]}
        if method == "GET" and path == "/v1/profiles":
            # Only what Apple documents for this endpoint; anything else is a 400.
            allowed = {"filter[profileType]", "filter[profileState]", "include", "limit", "cursor"}
            if set(query) - allowed or set(query["include"][0].split(",")) - {"bundleId", "certificates", "devices"}:
                return 400, {"errors": [{"code": "PARAMETER_ERROR.INVALID", "title": "unsupported parameter"}]}
            data = [p for p in self.profiles if p["attributes"]["profileType"] == query["filter[profileType]"][0]
                    and p["attributes"]["profileState"] == query["filter[profileState]"][0]]
            return 200, {"data": data}
        if method == "POST" and path == "/v1/profiles":
            rel = body["data"]["relationships"]
            bid = rel["bundleId"]["data"]["id"]
            ident = next(i for i, b in self.bundles.items() if b["id"] == bid)
            certs = [c["id"] for c in rel["certificates"]["data"]]
            self.created += 1
            res = profile_resource(f"new{self.created}-{bid}", ident, certs)
            res["attributes"]["name"] = body["data"]["attributes"]["name"]
            assert body["data"]["attributes"]["profileType"] == "MAC_APP_DIRECT"
            self.profiles.append(res)
            return 201, {"data": res}
        return 404, {"errors": [{"code": "NOT_FOUND", "title": path}]}


def serve(fake: FakeAsc):
    class H(BaseHTTPRequestHandler):
        def _do(self):
            u = urlparse(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n)) if n else None
            status, payload = fake.handle(self.command, u.path, parse_qs(u.query), body, self.headers.get("Authorization"))
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        do_GET = do_POST = _do

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class EnsureTests(tv.WithFakes):
    script = SCRIPT

    def setUp(self):
        super().setUp()
        self.key = self.tmp / "AuthKey.p8"
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", str(self.key)], check=True, capture_output=True)
        pub = self.tmp / "pub.pem"
        subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout", "-out", str(pub)], check=True, capture_output=True)
        self.fake = FakeAsc(pub)
        self.server = serve(self.fake)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.cert_pem = self.tmp / "cert.pem"
        self.cert_pem.write_text(pem(CERT_DER))
        self.dirs = [self.tmp / "installA", self.tmp / "installB"]
        self.state, self.env_out = self.tmp / "state.json", self.tmp / "env.out"

    def ensure(self, cert_pem=None):
        args = ["ensure", "--key", self.key, "--key-id", KEY_ID, "--issuer", ISSUER,
                "--cert-pem", cert_pem or self.cert_pem, "--state", self.state, "--env-out", self.env_out,
                "--api-base", f"http://127.0.0.1:{self.server.server_port}"]
        for d in self.dirs:
            args += ["--install-dir", d]
        return self.run_cli(*args)

    def cleanup(self):
        return self.run_cli("cleanup", "--state", self.state)

    def installed(self):
        return sorted(p.name for d in self.dirs for p in d.glob("*") if d.exists())

    def posts(self):
        return [r for r in self.fake.requests if r[0] == "POST"]

    def test_creates_all_three_profiles_installs_and_cleans_up_exactly(self):
        # An unrelated profile in the install dir must survive cleanup.
        self.dirs[0].mkdir()
        bystander = self.dirs[0] / "unrelated.provisionprofile"
        bystander.write_bytes(b"keep me")
        r = self.ensure()
        self.assertEqual((r.returncode, r.stderr), (0, ""), r.stdout)
        self.assertEqual(len(self.posts()), 3)
        env = dict(line.split("=", 1) for line in self.env_out.read_text().splitlines())
        self.assertEqual(sorted(env), ["YADORILINK_FILEPROVIDER_PROFILE_FILE", "YADORILINK_FINDERSYNC_PROFILE_FILE", "YADORILINK_HOST_PROFILE_FILE"])
        for path in env.values():
            self.assertEqual(Path(path).parent, self.dirs[0])
            for d in self.dirs:
                self.assertTrue((d / Path(path).name).is_file())
        self.assertEqual(len(json.loads(self.state.read_text())["files"]), 6)
        self.assertEqual(self.cleanup().returncode, 0)
        self.assertEqual(self.installed(), ["unrelated.provisionprofile"])
        self.assertEqual(bystander.read_bytes(), b"keep me")

    def test_reuses_a_valid_existing_profile_without_creating(self):
        self.fake.profiles.append(profile_resource("p1", FINDER, ["C-ours"]))
        self.fake.profiles.append(profile_resource("p2", PROVIDER, ["C-ours"]))
        self.fake.profiles.append(profile_resource("p0", HOST, ["C-ours"]))
        r = self.ensure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.posts(), [])
        self.assertIn("UUID-p0", self.env_out.read_text())
        self.assertIn("reused", r.stdout)
        self.assertIn("UUID-p1", self.env_out.read_text())

    def test_unusable_existing_profiles_are_replaced(self):
        finder = [
            profile_resource("inv", FINDER, ["C-ours"], state="INVALID"),
            profile_resource("dev", FINDER, ["C-ours"], ptype="MAC_APP_DEVELOPMENT"),
            profile_resource("othercert", FINDER, ["C-other"]),
            profile_resource("nogroup", FINDER, ["C-ours"], ents={vmp.GROUPS_KEY: None}),
            profile_resource("wrongder", FINDER, ["C-ours"], ders=(OTHER_DER,)),
            profile_resource("wrongapp", FINDER, ["C-ours"], ents={"com.apple.application-identifier": f"{vmp.TEAM_ID}.com.example.x"}),
        ]
        self.fake.profiles += finder
        r = self.ensure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.posts()), 3)  # FinderSync replaced, the others had none
        self.assertIn("skipping profile 'existing nogroup'", r.stdout)
        self.assertIn("skipping profile 'existing wrongder'", r.stdout)
        self.assertNotIn("UUID-inv", self.env_out.read_text())

    def test_profile_of_another_bundle_id_is_not_reused(self):
        self.fake.profiles.append(profile_resource("p2", PROVIDER, ["C-ours"]))
        r = self.ensure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.posts()), 2)  # FinderSync and the host needed new ones
        self.assertIn("UUID-p2", self.env_out.read_text())

    def test_developer_id_g2_certificate_is_found(self):
        self.fake.certs[1]["attributes"]["certificateType"] = "DEVELOPER_ID_APPLICATION_G2"
        r = self.ensure()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_certificate_must_match_the_imported_one_byte_for_byte(self):
        self.cert_pem.write_text(pem(b"not-in-the-team"))
        r = self.ensure()
        self.assertEqual(r.returncode, 1)
        self.assertIn("not among the team's 2", r.stderr)
        self.assertEqual((self.posts(), self.installed()), ([], []))
        self.assertFalse(self.env_out.exists())

    def test_certificate_listing_is_paged(self):
        # The matching certificate is on the second page in the fake.
        r = self.ensure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertGreaterEqual(sum(1 for q in self.fake.requests if q[1] == "/v1/certificates"), 2)

    def test_403_fails_fast_with_actionable_message(self):
        self.fake.force_status = 403
        r = self.ensure()
        self.assertEqual(r.returncode, 1)
        self.assertIn("HTTP 403", r.stderr)
        self.assertIn("Admin or App Manager", r.stderr)
        self.assertEqual(len(self.fake.requests), 1)
        self.assertEqual(self.installed(), [])

    def test_bad_token_reports_401(self):
        self.key.write_text(self.key.read_text())  # same key...
        self.fake.pubkey = self.tmp / "absent.pem"  # ...but the server verifies against another one
        r = self.ensure()
        self.assertEqual(r.returncode, 1)
        self.assertIn("HTTP 401", r.stderr)

    def test_missing_bundle_id_and_missing_capability(self):
        del self.fake.bundles[PROVIDER]
        r = self.ensure()
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"Bundle id {PROVIDER} is not registered", r.stderr)
        self.cleanup()
        self.fake.bundles[PROVIDER] = {"id": "B-provider", "caps": []}
        r = self.ensure()
        self.assertEqual(r.returncode, 1)
        self.assertIn("App Groups capability", r.stderr)

    def test_host_bundle_id_is_required_with_the_app_groups_capability(self):
        # The host's id is a prefix of both extensions' ids: they must not stand in for it.
        del self.fake.bundles[HOST]
        r = self.ensure()
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"Bundle id {HOST} is not registered", r.stderr)
        self.assertEqual((self.posts(), self.installed()), ([], []))
        self.cleanup()
        self.fake.bundles[HOST] = {"id": "B-host", "caps": ["PUSH_NOTIFICATIONS"]}
        r = self.ensure()
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"Bundle id {HOST} does not have the App Groups capability", r.stderr)
        self.assertFalse(self.env_out.exists())

    def test_host_profile_is_never_reused_for_an_extension(self):
        self.fake.profiles.append(profile_resource("h", HOST, ["C-ours"]))
        r = self.ensure()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.posts()), 2)
        env = dict(line.split("=", 1) for line in self.env_out.read_text().splitlines())
        self.assertIn("UUID-h", env["YADORILINK_HOST_PROFILE_FILE"])
        self.assertNotIn("UUID-h", env["YADORILINK_FINDERSYNC_PROFILE_FILE"])
        self.assertNotIn("UUID-h", env["YADORILINK_FILEPROVIDER_PROFILE_FILE"])

    def test_logs_no_secrets(self):
        r = self.ensure()
        combined = r.stdout + r.stderr
        tokens = {auth[7:] for _, _, auth in self.fake.requests}
        self.assertTrue(tokens)
        for secret in tokens | {self.key.read_text().splitlines()[1], str(self.key)}:
            self.assertNotIn(secret, combined)
        for res in self.fake.profiles:
            self.assertNotIn(res["attributes"]["profileContent"], combined)
        self.assertIn("uuid=UUID-new1-B-host", combined)

    def test_conflicting_file_aborts_and_cleanup_removes_only_what_was_created(self):
        self.dirs[1].mkdir()
        # Whatever UUID the first profile gets, pre-seed a different file under it in dir B.
        (self.dirs[1] / "UUID-new1-B-host.provisionprofile").write_bytes(b"someone else's")
        r = self.ensure()
        self.assertEqual(r.returncode, 1)
        self.assertIn("refusing to overwrite", r.stderr)
        self.assertEqual(self.installed(), ["UUID-new1-B-host.provisionprofile"] * 2)
        self.cleanup()
        self.assertEqual([p.name for p in self.dirs[1].glob("*")], ["UUID-new1-B-host.provisionprofile"])
        self.assertEqual((self.dirs[1] / "UUID-new1-B-host.provisionprofile").read_bytes(), b"someone else's")
        self.assertEqual(list(self.dirs[0].glob("*")), [])

    def test_identical_preexisting_file_is_left_alone_by_cleanup(self):
        self.assertEqual(self.ensure().returncode, 0)
        before = self.installed()
        self.cleanup()
        self.assertEqual(self.installed(), [])
        # run again with a pre-seeded identical copy in dir A
        res = self.fake.profiles[0]
        self.dirs[0].mkdir(exist_ok=True)
        seeded = self.dirs[0] / "UUID-new1-B-host.provisionprofile"
        seeded.write_bytes(base64.b64decode(res["attributes"]["profileContent"]))
        self.assertEqual(self.ensure().returncode, 0)
        self.cleanup()
        self.assertTrue(seeded.exists())
        self.assertEqual(len(before), 6)

    def test_cleanup_without_state_is_a_noop(self):
        self.assertEqual(self.cleanup().returncode, 0)


class InstallTests(unittest.TestCase):
    def test_failed_write_is_still_recorded_for_cleanup(self):
        import unittest.mock
        mod = ensure_mod()
        with tempfile.TemporaryDirectory(prefix="install-test-") as d:
            created = []
            with unittest.mock.patch.object(mod.os, "fdopen", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    mod.install(b"data", "U1", [d], created)
            # The file exists (created, not written) and cleanup knows about it.
            self.assertEqual(created, [str(Path(d, "U1.provisionprofile"))])
            self.assertTrue(Path(created[0]).exists())

    def test_second_directory_failure_keeps_the_first_file_recorded(self):
        mod = ensure_mod()
        with tempfile.TemporaryDirectory(prefix="install-test-") as d:
            blocker = Path(d, "not-a-dir")
            blocker.write_text("x")
            created = []
            with self.assertRaises(OSError):
                mod.install(b"data", "U1", [str(Path(d, "ok")), str(blocker)], created)
            self.assertEqual(created, [str(Path(d, "ok", "U1.provisionprofile"))])


class Jwt(unittest.TestCase):
    def test_der_to_raw_signature_roundtrip_with_short_integers(self):
        for r, s in ((1, 2), (2**255 + 5, 7), (2**256 - 1, 2**255)):
            raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            self.assertEqual(ensure_mod().der_to_raw_signature(raw_to_der(raw)), raw)


def ensure_mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ensure_macos_profiles", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


if __name__ == "__main__":
    unittest.main()
