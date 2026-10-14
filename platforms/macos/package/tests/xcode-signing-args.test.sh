#!/bin/bash
# Tests of xcode-signing-args.sh: the argument lists for each mode, and (when
# Xcode is installed) the per-target build settings those arguments resolve to.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ_DIR="$HERE/../../app/YadoriLinkFinderSync"
# shellcheck source=../xcode-signing-args.sh
source "$HERE/../xcode-signing-args.sh"

FAILS=0
fail() { echo "FAIL: $*" >&2; FAILS=$((FAILS + 1)); }
joined() { local IFS=$'\x1f'; echo "${XCODE_SIGNING_ARGS[*]}"; }
has() { case "$(joined)" in *"$1"*) return 0 ;; *) return 1 ;; esac; }
clean_env() {
    unset YADORILINK_RELEASE_BUILD YADORILINK_APP_SIGN_IDENTITY YADORILINK_XCODE_PROFILE_EXPERIMENT \
        YADORILINK_FINDERSYNC_PROFILE YADORILINK_FILEPROVIDER_PROFILE \
        YADORILINK_NOTARY_KEY YADORILINK_NOTARY_KEY_ID YADORILINK_NOTARY_ISSUER
}
ID="Developer ID Application: Example (594UQF7QX3)"

# development: Automatic (nothing overridden), provisioning updates allowed
clean_env
xcode_signing_args || fail "dev: returned non-zero"
[ "$(joined)" = "-allowProvisioningUpdates" ] || fail "dev: unexpected args: $(joined)"

# release, default: Manual + identity + timestamp + the two profiles, no Xcode account
clean_env
export YADORILINK_RELEASE_BUILD=1 YADORILINK_APP_SIGN_IDENTITY="$ID"
export YADORILINK_FINDERSYNC_PROFILE=fs-uuid YADORILINK_FILEPROVIDER_PROFILE=fp-uuid
export YADORILINK_NOTARY_KEY=/secret/key.p8 YADORILINK_NOTARY_KEY_ID=KID YADORILINK_NOTARY_ISSUER=ISS
xcode_signing_args || fail "release: returned non-zero"
for want in CODE_SIGN_STYLE=Manual "CODE_SIGN_IDENTITY=$ID" OTHER_CODE_SIGN_FLAGS=--timestamp \
    YADORILINK_FINDERSYNC_PROFILE=fs-uuid YADORILINK_FILEPROVIDER_PROFILE=fp-uuid; do
    has "$want" || fail "release: missing $want in $(joined)"
done
for unwanted in allowProvisioningUpdates authentication /secret/key.p8; do
    has "$unwanted" && fail "release: must not contain $unwanted"
done
RELEASE_ARGS=("${XCODE_SIGNING_ARGS[@]}")

# release: each required input missing fails
for var in YADORILINK_APP_SIGN_IDENTITY YADORILINK_FINDERSYNC_PROFILE YADORILINK_FILEPROVIDER_PROFILE; do
    ( unset "$var"; xcode_signing_args 2>/dev/null ) && fail "release without $var must fail"
done

# experiment: Xcode creates profiles with the API key; no manual profile variables
export YADORILINK_XCODE_PROFILE_EXPERIMENT=1
xcode_signing_args || fail "experiment: returned non-zero"
for want in -allowProvisioningUpdates "-authenticationKeyPath"$'\x1f'/secret/key.p8 \
    "-authenticationKeyID"$'\x1f'KID "-authenticationKeyIssuerID"$'\x1f'ISS "CODE_SIGN_IDENTITY=$ID" OTHER_CODE_SIGN_FLAGS=--timestamp; do
    has "$want" || fail "experiment: missing $want"
done
has CODE_SIGN_STYLE=Manual && fail "experiment must leave signing style Automatic"
has YADORILINK_FINDERSYNC_PROFILE && fail "experiment must not pin profiles"
for var in YADORILINK_NOTARY_KEY YADORILINK_NOTARY_KEY_ID YADORILINK_NOTARY_ISSUER; do
    ( unset "$var"; xcode_signing_args 2>/dev/null ) && fail "experiment without $var must fail"
done

# Resolved per-target settings (needs Xcode): only the extensions get a profile
if command -v xcodebuild >/dev/null && [ -d "$PROJ_DIR/YadoriLinkFinderSync.xcodeproj" ]; then
    setting() { # target name
        ( cd "$PROJ_DIR" && xcodebuild -project YadoriLinkFinderSync.xcodeproj -target "$1" \
            -configuration Release -showBuildSettings "${RELEASE_ARGS[@]}" 2>/dev/null \
            | awk -v k="$2" '$1 == k && $2 == "=" { sub(/^[^=]*= ?/, ""); print; exit }' )
    }
    for target in YadoriLink YadoriLinkFinderSync YadoriLinkFileProvider YadoriLinkFFI; do
        [ "$(setting "$target" CODE_SIGN_STYLE)" = Manual ] || fail "$target: CODE_SIGN_STYLE is not Manual"
        [ "$(setting "$target" CODE_SIGN_IDENTITY)" = "$ID" ] || fail "$target: wrong CODE_SIGN_IDENTITY"
        [ "$(setting "$target" OTHER_CODE_SIGN_FLAGS)" = "--timestamp" ] || fail "$target: no secure timestamp"
        [ "$(setting "$target" ENABLE_HARDENED_RUNTIME)" = YES ] || fail "$target: hardened runtime off"
    done
    [ "$(setting YadoriLinkFinderSync PROVISIONING_PROFILE_SPECIFIER)" = fs-uuid ] || fail "FinderSync profile not fs-uuid"
    [ "$(setting YadoriLinkFileProvider PROVISIONING_PROFILE_SPECIFIER)" = fp-uuid ] || fail "FileProvider profile not fp-uuid"
    [ -z "$(setting YadoriLink PROVISIONING_PROFILE_SPECIFIER)" ] || fail "host app must have no profile"
    [ -z "$(setting YadoriLink CODE_SIGN_ENTITLEMENTS)" ] || fail "host app must have no entitlements file"
    [ -z "$(setting YadoriLinkFFI PROVISIONING_PROFILE_SPECIFIER)" ] || fail "framework must have no profile"
    # Development settings (no overrides) stay Automatic and profile-free.
    dev() { ( cd "$PROJ_DIR" && env -u YADORILINK_FINDERSYNC_PROFILE -u YADORILINK_FILEPROVIDER_PROFILE xcodebuild -project YadoriLinkFinderSync.xcodeproj -target "$1" \
        -configuration Release -showBuildSettings 2>/dev/null | awk -v k="$2" '$1 == k && $2 == "=" { sub(/^[^=]*= ?/, ""); print; exit }' ); }
    [ "$(dev YadoriLinkFinderSync CODE_SIGN_STYLE)" = Automatic ] || fail "dev FinderSync is not Automatic"
    [ -z "$(dev YadoriLinkFinderSync PROVISIONING_PROFILE_SPECIFIER)" ] || fail "dev FinderSync has a profile specifier"
else
    echo "SKIP: xcodebuild or project not available; per-target settings not checked"
fi

if [ "$FAILS" -ne 0 ]; then echo "$FAILS failure(s)" >&2; exit 1; fi
echo "xcode-signing-args tests passed"
