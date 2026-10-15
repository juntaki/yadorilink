"""Tests of validate-macos-profiles.py against synthetic profiles.

`security` and `codesign` are replaced by tiny fakes on PATH: the fake
`security cms -D -i FILE` prints the file (so a fixture is a plain plist), and
the fake `codesign -d --entitlements :- ITEM` prints the entitlements fixture
named after the item's basename.

Run: python3 -m unittest discover -s platforms/macos/package/tests
"""

import datetime
import importlib.util
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "validate-macos-profiles.py"
spec = importlib.util.spec_from_file_location("validate_macos_profiles", SCRIPT)
vmp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vmp)

NOW = datetime.datetime(2026, 10, 12, tzinfo=datetime.timezone.utc)
HOST = "com.juntaki.yadorilink"
FINDER = "com.juntaki.yadorilink.FinderSync"
PROVIDER = "com.juntaki.yadorilink.FileProvider"

FAKE_SECURITY = """#!/bin/sh
[ "$1 $2 $3" = "cms -D -i" ] || exit 64
cat "$4" || exit 1
"""
FAKE_CODESIGN = """#!/bin/sh
for last; do :; done
f="$FAKE_ENT_DIR/$(basename "$last").plist"
[ -f "$f" ] && cat "$f"
exit 0
"""


def make_profile(bundle_id=FINDER, **over):
    p = {
        "UUID": "11111111-2222-3333-4444-555555555555",
        "Name": "yadorilink test",
        "TeamIdentifier": [vmp.TEAM_ID],
        "ExpirationDate": NOW + datetime.timedelta(days=300),
        "Entitlements": {
            "com.apple.application-identifier": f"{vmp.TEAM_ID}.{bundle_id}",
            "com.apple.developer.team-identifier": vmp.TEAM_ID,
            vmp.GROUPS_KEY: [vmp.APP_GROUP],
        },
    }
    for key, value in over.pop("ents", {}).items():
        if value is None:
            p["Entitlements"].pop(key, None)
        else:
            p["Entitlements"][key] = value
    for key, value in over.items():
        if value is None:
            p.pop(key, None)
        else:
            p[key] = value
    return p


class ProfileProblems(unittest.TestCase):
    def problems(self, profile, bundle_id=FINDER, **kw):
        return vmp.profile_problems(profile, bundle_id, NOW, **kw)

    def test_valid_profile_has_no_problems(self):
        self.assertEqual(self.problems(make_profile()), [])
        self.assertEqual(self.problems(make_profile(PROVIDER), PROVIDER), [])
        self.assertEqual(self.problems(make_profile(HOST), HOST), [])

    def test_host_profile_must_not_pass_for_an_extension_and_vice_versa(self):
        self.assertTrue(any("application identifier" in x for x in self.problems(make_profile(HOST), FINDER)))
        self.assertTrue(any("application identifier" in x for x in self.problems(make_profile(FINDER), HOST)))

    def test_host_profile_without_app_group_is_rejected(self):
        p = make_profile(HOST, ents={vmp.GROUPS_KEY: None})
        self.assertTrue(any("App Group" in x for x in self.problems(p, HOST)))

    def test_ios_style_application_identifier_key_is_accepted(self):
        p = make_profile()
        ents = p["Entitlements"]
        ents["application-identifier"] = ents.pop("com.apple.application-identifier")
        self.assertEqual(self.problems(p), [])

    def test_wrong_team(self):
        p = make_profile(TeamIdentifier=["OTHERTEAM1"])
        self.assertTrue(any("TeamIdentifier" in x for x in self.problems(p)))

    def test_wrong_bundle_id_suffix(self):
        # A FileProvider profile must not pass for FinderSync.
        self.assertTrue(any("application identifier" in x for x in self.problems(make_profile(PROVIDER), FINDER)))

    def test_wildcard_application_identifier_is_rejected(self):
        p = make_profile()
        p["Entitlements"]["com.apple.application-identifier"] = f"{vmp.TEAM_ID}.*"
        self.assertTrue(any("application identifier" in x for x in self.problems(p)))

    def test_team_prefix_must_match_in_application_identifier(self):
        p = make_profile()
        p["Entitlements"]["com.apple.application-identifier"] = f"OTHERTEAM1.{FINDER}"
        self.assertTrue(any("application identifier" in x for x in self.problems(p)))

    def test_missing_app_group(self):
        p = make_profile(ents={vmp.GROUPS_KEY: None})
        self.assertTrue(any("App Group" in x for x in self.problems(p)))

    def test_other_app_group_only(self):
        p = make_profile(ents={vmp.GROUPS_KEY: ["group.example.other"]})
        self.assertTrue(any("App Group" in x for x in self.problems(p)))

    def test_expired(self):
        p = make_profile(ExpirationDate=NOW - datetime.timedelta(seconds=1))
        self.assertTrue(any("expired" in x for x in self.problems(p)))

    def test_expiring_inside_margin(self):
        p = make_profile(ExpirationDate=NOW + datetime.timedelta(hours=2))
        self.assertTrue(any("expired" in x for x in self.problems(p)))
        self.assertEqual(self.problems(p, min_days=0), [])

    def test_missing_expiration(self):
        self.assertTrue(any("ExpirationDate" in x for x in self.problems(make_profile(ExpirationDate=None))))

    def test_development_profile_shapes(self):
        self.assertTrue(self.problems(make_profile(ProvisionedDevices=["00008103-AAAA"])))
        self.assertTrue(self.problems(make_profile(ents={"com.apple.security.get-task-allow": True})))

    def test_all_problems_are_reported_together(self):
        p = make_profile(TeamIdentifier=["X"], ents={vmp.GROUPS_KEY: None})
        self.assertGreaterEqual(len(self.problems(p)), 2)


class WithFakes(unittest.TestCase):
    script = SCRIPT

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="validate-profiles-")
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        bindir = self.tmp / "bin"
        bindir.mkdir()
        for name, body in (("security", FAKE_SECURITY), ("codesign", FAKE_CODESIGN)):
            path = bindir / name
            path.write_text(body)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.ent_dir = self.tmp / "ents"
        self.ent_dir.mkdir()
        self.env = dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}", FAKE_ENT_DIR=str(self.ent_dir))

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(self.script), *map(str, args)], capture_output=True, text=True, env=self.env
        )

    def write(self, path: Path, data: dict) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(plistlib.dumps(data))
        return path


@unittest.skipUnless(sys.platform == "darwin", "needs /usr/bin/security")
class RealSecurityDecode(unittest.TestCase):
    def test_decodes_a_cms_signed_profile(self):
        with tempfile.TemporaryDirectory(prefix="real-security-") as d:
            d = Path(d)
            plist = d / "p.plist"
            plist.write_bytes(plistlib.dumps(make_profile()))
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", d / "k.pem",
                 "-out", d / "c.pem", "-subj", "/CN=test", "-days", "2"],
                check=True, capture_output=True)
            subprocess.run(
                ["openssl", "cms", "-sign", "-in", plist, "-signer", d / "c.pem", "-inkey", d / "k.pem",
                 "-nodetach", "-outform", "DER", "-out", d / "x.provisionprofile"],
                check=True, capture_output=True)
            profile = vmp.decode_profile(d / "x.provisionprofile")
            self.assertEqual(vmp.profile_problems(profile, FINDER, NOW), [])
            with self.assertRaises(vmp.ProfileError):
                vmp.decode_profile(plist)  # a bare plist is not a CMS envelope


class ProfileCli(WithFakes):
    def test_valid_profile_prints_uuid(self):
        f = self.write(self.tmp / "a.provisionprofile", make_profile())
        r = self.run_cli("profile", f, "--bundle-id", FINDER, "--print-uuid")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "11111111-2222-3333-4444-555555555555"))

    def test_invalid_profile_exits_nonzero_with_reason(self):
        f = self.write(self.tmp / "a.provisionprofile", make_profile(PROVIDER))
        r = self.run_cli("profile", f, "--bundle-id", FINDER)
        self.assertEqual(r.returncode, 1)
        self.assertIn("application identifier", r.stderr)
        self.assertEqual(r.stdout, "")

    def test_undecodable_profile(self):
        f = self.tmp / "junk.provisionprofile"
        f.write_text("not a plist")
        r = self.run_cli("profile", f, "--bundle-id", FINDER)
        self.assertEqual(r.returncode, 1)
        self.assertIn("not a plist", r.stderr)

    def test_missing_profile_file(self):
        r = self.run_cli("profile", self.tmp / "absent.provisionprofile", "--bundle-id", FINDER)
        self.assertEqual(r.returncode, 1)


def ext_ents(group=vmp.APP_GROUP, **extra):
    return {vmp.GROUPS_KEY: [group], "com.apple.security.app-sandbox": True, **extra}


def host_ents(group=vmp.APP_GROUP, **extra):
    # The host app is not sandboxed: only the App Group.
    return {vmp.GROUPS_KEY: [group], **extra}


class BuiltApp(WithFakes):
    def build_app(self, host=None, host_ents_=None, finder=None, provider=None, finder_ents=None, provider_ents=None, bundle_ids=None):
        """A profile argument of False omits that embedded profile."""
        bundle_ids = bundle_ids or {}
        app = self.tmp / "YadoriLink.app"
        plugins = app / "Contents" / "PlugIns"
        for rel, bid in (("", HOST), ("Contents/PlugIns/YadoriLinkFinderSync.appex", FINDER),
                         ("Contents/PlugIns/YadoriLinkFileProvider.appex", PROVIDER)):
            self.write((app / rel if rel else app) / "Contents/Info.plist", {"CFBundleIdentifier": bundle_ids.get(rel, bid)})
        if finder is not False:
            self.write(plugins / "YadoriLinkFinderSync.appex/Contents/embedded.provisionprofile", finder or make_profile(FINDER))
        if provider is not False:
            self.write(plugins / "YadoriLinkFileProvider.appex/Contents/embedded.provisionprofile", provider or make_profile(PROVIDER))
        if host is not False:
            self.write(app / "Contents/embedded.provisionprofile", host or make_profile(HOST))
        self.write(self.ent_dir / "YadoriLink.app.plist", host_ents_ if host_ents_ is not None else host_ents())
        self.write(self.ent_dir / "YadoriLinkFinderSync.appex.plist", finder_ents or ext_ents())
        self.write(self.ent_dir / "YadoriLinkFileProvider.appex.plist", provider_ents or ext_ents())
        return app

    def test_expected_shape_passes(self):
        r = self.run_cli("built-app", self.build_app())
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        for name in ("YadoriLink.app", "YadoriLinkFinderSync.appex", "YadoriLinkFileProvider.appex"):
            self.assertIn(f"OK {name}", r.stdout)

    def test_host_without_embedded_profile_fails(self):
        r = self.run_cli("built-app", self.build_app(host=False))
        self.assertEqual(r.returncode, 1)
        self.assertIn("YadoriLink.app embeds no provisioning profile", r.stderr)

    def test_host_with_extension_profile_fails(self):
        r = self.run_cli("built-app", self.build_app(host=make_profile(FINDER)))
        self.assertEqual(r.returncode, 1)
        self.assertIn("application identifier", r.stderr)

    def test_extension_with_host_profile_fails(self):
        r = self.run_cli("built-app", self.build_app(provider=make_profile(HOST)))
        self.assertEqual(r.returncode, 1)
        self.assertIn("application identifier", r.stderr)

    def test_host_profile_without_app_group_fails(self):
        r = self.run_cli("built-app", self.build_app(host=make_profile(HOST, ents={vmp.GROUPS_KEY: None})))
        self.assertEqual(r.returncode, 1)
        self.assertIn("App Group", r.stderr)

    def test_expired_host_profile_fails(self):
        expired = make_profile(HOST, ExpirationDate=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        r = self.run_cli("built-app", self.build_app(host=expired))
        self.assertEqual(r.returncode, 1)
        self.assertIn("expired", r.stderr)

    def test_host_signing_no_app_group_fails(self):
        for ents in ({}, {"com.apple.security.cs.allow-jit": True}):
            r = self.run_cli("built-app", self.build_app(host_ents_=ents))
            self.assertEqual(r.returncode, 1)
            self.assertIn("YadoriLink.app signs no App Group", r.stderr)

    def test_host_with_no_entitlements_at_all_fails(self):
        app = self.build_app()
        (self.ent_dir / "YadoriLink.app.plist").unlink()  # codesign prints nothing
        r = self.run_cli("built-app", app)
        self.assertEqual(r.returncode, 1)
        self.assertIn("YadoriLink.app signs no App Group", r.stderr)

    def test_host_signed_group_the_profile_does_not_authorize_fails(self):
        r = self.run_cli("built-app", self.build_app(host_ents_=host_ents(group="group.example.other")))
        self.assertEqual(r.returncode, 1)
        self.assertIn("YadoriLink.app signs App Group group.example.other that its profile does not authorize", r.stderr)

    def test_host_get_task_allow_fails(self):
        r = self.run_cli("built-app", self.build_app(host_ents_=host_ents(**{"com.apple.security.get-task-allow": True})))
        self.assertEqual(r.returncode, 1)
        self.assertIn("YadoriLink.app signs get-task-allow", r.stderr)

    def test_signed_application_identifier_must_match_the_profile(self):
        r = self.run_cli("built-app", self.build_app(
            host_ents_=host_ents(**{"com.apple.application-identifier": f"{vmp.TEAM_ID}.com.example.other"})))
        self.assertEqual(r.returncode, 1)
        self.assertIn("YadoriLink.app signs application identifier", r.stderr)
        ok = self.build_app(host_ents_=host_ents(**{"com.apple.application-identifier": f"{vmp.TEAM_ID}.{HOST}"}))
        self.assertEqual(self.run_cli("built-app", ok).returncode, 0)

    def test_bundle_identifier_must_match_the_profile_target(self):
        for rel, bid in (("", FINDER), ("Contents/PlugIns/YadoriLinkFileProvider.appex", HOST)):
            r = self.run_cli("built-app", self.build_app(bundle_ids={rel: bid}))
            self.assertEqual(r.returncode, 1)
            self.assertIn("CFBundleIdentifier", r.stderr)

    def test_missing_extension_fails(self):
        app = self.build_app()
        import shutil
        shutil.rmtree(app / "Contents/PlugIns/YadoriLinkFinderSync.appex")
        r = self.run_cli("built-app", app)
        self.assertEqual(r.returncode, 1)
        self.assertIn("YadoriLinkFinderSync.appex is missing", r.stderr)

    def test_extension_get_task_allow_fails(self):
        r = self.run_cli("built-app", self.build_app(provider_ents=ext_ents(**{"com.apple.security.get-task-allow": True})))
        self.assertEqual(r.returncode, 1)
        self.assertIn("YadoriLinkFileProvider.appex signs get-task-allow", r.stderr)

    def test_extension_without_embedded_profile_fails(self):
        r = self.run_cli("built-app", self.build_app(provider=False))
        self.assertEqual(r.returncode, 1)
        self.assertIn("YadoriLinkFileProvider.appex", r.stderr)

    def test_swapped_extension_profiles_fail(self):
        r = self.run_cli("built-app", self.build_app(finder=make_profile(PROVIDER), provider=make_profile(FINDER)))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stderr.count("application identifier"), 2)

    def test_expired_embedded_profile_fails(self):
        expired = make_profile(PROVIDER, ExpirationDate=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        r = self.run_cli("built-app", self.build_app(provider=expired))
        self.assertEqual(r.returncode, 1)
        self.assertIn("expired", r.stderr)

    def test_signed_group_the_profile_does_not_authorize_fails(self):
        r = self.run_cli("built-app", self.build_app(finder_ents=ext_ents(group="group.example.other")))
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not authorize", r.stderr)

    def test_extension_signing_no_group_fails(self):
        r = self.run_cli("built-app", self.build_app(finder_ents={"com.apple.security.app-sandbox": True}))
        self.assertEqual(r.returncode, 1)
        self.assertIn("signs no App Group", r.stderr)


if __name__ == "__main__":
    unittest.main()
