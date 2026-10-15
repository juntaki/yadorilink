#!/bin/bash
# Tests of the teardown and profile-source halves of .github/release/macos-signing.sh,
# with a fake `security`: it must delete the keychain and the key material,
# remove exactly the provisioning-profile files recorded in the state file,
# and succeed even when nothing was set up.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../../../../.github/release/macos-signing.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keychain-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
fail() { echo "FAIL: $*" >&2; FAILS=$((FAILS + 1)); }

mkdir -p "$WORK/bin" "$WORK/runner" "$WORK/profiles"
cat > "$WORK/bin/security" <<'FAKE'
#!/bin/sh
echo "$*" >> "$FAKE_SECURITY_LOG"
FAKE
chmod +x "$WORK/bin/security"
export FAKE_SECURITY_LOG="$WORK/security.log"
export PATH="$WORK/bin:$PATH" RUNNER_TEMP="$WORK/runner"

# nothing set up: still succeeds
SIGNING_KEYCHAIN="" NOTARY_KEY_PATH="" APP_CERT_PEM="" bash "$SCRIPT" teardown || fail "teardown with nothing set up failed"

# everything set up, plus a profile state naming two files and a bystander
echo p > "$WORK/profiles/a.provisionprofile"; echo p > "$WORK/profiles/b.provisionprofile"
echo keep > "$WORK/profiles/bystander.provisionprofile"
printf '{"files": ["%s", "%s"]}' "$WORK/profiles/a.provisionprofile" "$WORK/profiles/b.provisionprofile" \
    > "$RUNNER_TEMP/macos-profiles-state.json"
echo k > "$RUNNER_TEMP/notary.p8"; echo c > "$RUNNER_TEMP/app-cert.pem"; echo x > "$RUNNER_TEMP/app.p12"
bash "$SCRIPT" teardown || fail "teardown failed"
grep -q "delete-keychain $RUNNER_TEMP/yadorilink-signing.keychain-db" "$FAKE_SECURITY_LOG" || fail "keychain not deleted"
for f in notary.p8 app-cert.pem app.p12; do [ ! -e "$RUNNER_TEMP/$f" ] || fail "$f not removed"; done
[ ! -e "$WORK/profiles/a.provisionprofile" ] && [ ! -e "$WORK/profiles/b.provisionprofile" ] || fail "recorded profiles not removed"
[ -e "$WORK/profiles/bystander.provisionprofile" ] || fail "unrelated profile was removed"

# setup died before exporting anything: teardown still finds the fixed keychain
: > "$FAKE_SECURITY_LOG"
echo p12 > "$RUNNER_TEMP/app.p12"; echo bystander > "$RUNNER_TEMP/other.p12"
env -u SIGNING_KEYCHAIN -u NOTARY_KEY_PATH -u APP_CERT_PEM bash "$SCRIPT" teardown || fail "teardown without exported paths failed"
grep -q "delete-keychain $RUNNER_TEMP/yadorilink-signing.keychain-db" "$FAKE_SECURITY_LOG" || fail "default keychain not deleted"
[ ! -e "$RUNNER_TEMP/app.p12" ] || fail "setup's p12 not removed"
[ -e "$RUNNER_TEMP/other.p12" ] || fail "teardown removed a file setup did not write"

# a failing keychain delete must not fail the step
printf '#!/bin/sh\nexit 1\n' > "$WORK/bin/security"
SIGNING_KEYCHAIN=x bash "$SCRIPT" teardown || fail "teardown must succeed when security fails"

# profiles: an unknown source fails; the Xcode experiment leaves the env untouched
export GITHUB_ENV="$WORK/github.env"; : > "$GITHUB_ENV"
PROFILE_SOURCE=bogus bash "$SCRIPT" profiles 2>/dev/null && fail "unknown profile source must fail"
PROFILE_SOURCE=xcode-experiment bash "$SCRIPT" profiles >/dev/null || fail "xcode-experiment source failed"
[ ! -s "$GITHUB_ENV" ] || fail "xcode-experiment must not export profile paths"

[ "$FAILS" -eq 0 ] || { echo "$FAILS failure(s)" >&2; exit 1; }
echo "macos-signing teardown tests passed"
