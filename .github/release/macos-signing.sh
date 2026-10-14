#!/bin/bash
#
# .github/release/macos-signing.sh
#
# Sets up and tears down the signing material of a macOS release job. Used by
# every workflow that signs a macOS build, so they cannot drift apart.
#
#   setup     Import the Developer ID Application and Installer certificates
#             into a new keychain, write the notarization key to a file, and
#             append SIGNING_KEYCHAIN, NOTARY_KEY_PATH, APP_SIGN_IDENTITY,
#             PKG_SIGN_IDENTITY and APP_CERT_PEM to $GITHUB_ENV.
#             Reads APP_CERT_BASE64, APP_CERT_PASSWORD, INSTALLER_CERT_BASE64,
#             INSTALLER_CERT_PASSWORD, NOTARY_KEY_BASE64; uses $RUNNER_TEMP.
#   profiles  Make the two extension provisioning profiles available. With
#             PROFILE_SOURCE=api (the default) run ensure-macos-profiles.py
#             and append its YADORILINK_*_PROFILE_FILE paths to $GITHUB_ENV;
#             with PROFILE_SOURCE=xcode-experiment do nothing here (build-pkg.sh
#             lets Xcode create them). Reads NOTARY_KEY_ID, NOTARY_ISSUER_ID and,
#             from setup, NOTARY_KEY_PATH, APP_CERT_PEM.
#   teardown  Remove all of it, including the provisioning profiles that
#             ensure-macos-profiles.py installed (exactly the files it
#             recorded). Always exits 0 so it can run in an `if: always()` step.

set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP must be set}"
PROFILE_STATE="$RUNNER_TEMP/macos-profiles-state.json"
# Fixed names, so teardown finds them even when setup died before exporting them.
KEYCHAIN="$RUNNER_TEMP/yadorilink-signing.keychain-db"
APP_P12="$RUNNER_TEMP/app.p12"
INSTALLER_P12="$RUNNER_TEMP/installer.p12"
NOTARY_KEY_FILE="$RUNNER_TEMP/notary.p8"
APP_CERT_FILE="$RUNNER_TEMP/app-cert.pem"
PROFILES_ENV="$RUNNER_TEMP/macos-profiles.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENSURE_PROFILES="$SCRIPT_DIR/../../platforms/macos/package/ensure-macos-profiles.py"

setup() {
    : "${GITHUB_ENV:?GITHUB_ENV must be set}"
    local keychain="$KEYCHAIN"
    local keychain_password
    keychain_password="$(openssl rand -base64 24)"
    security create-keychain -p "$keychain_password" "$keychain"
    security set-keychain-settings -lut 21600 "$keychain"
    security unlock-keychain -p "$keychain_password" "$keychain"

    local app_p12="$APP_P12" installer_p12="$INSTALLER_P12"
    printf '%s' "$APP_CERT_BASE64" | base64 --decode > "$app_p12"
    printf '%s' "$INSTALLER_CERT_BASE64" | base64 --decode > "$installer_p12"
    security import "$app_p12" -k "$keychain" -P "$APP_CERT_PASSWORD" -T /usr/bin/codesign -T /usr/bin/productsign
    security import "$installer_p12" -k "$keychain" -P "$INSTALLER_CERT_PASSWORD" -T /usr/bin/codesign -T /usr/bin/productsign
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain" >/dev/null
    # shellcheck disable=SC2046
    security list-keychains -d user -s "$keychain" $(security list-keychains -d user | sed s/\"//g)

    local notary_key="$NOTARY_KEY_FILE"
    printf '%s' "$NOTARY_KEY_BASE64" | base64 --decode > "$notary_key"
    rm -f "$app_p12" "$installer_p12"

    local app_line app_identity app_hash installer_identity
    app_line="$(security find-identity -v -p codesigning "$keychain" | grep 'Developer ID Application' | head -1)"
    app_identity="$(printf '%s' "$app_line" | sed -E 's/.*"(.*)".*/\1/')"
    app_hash="$(printf '%s' "$app_line" | awk '{print $2}')"
    installer_identity="$(security find-identity -v "$keychain" | grep 'Developer ID Installer' | head -1 | sed -E 's/.*"(.*)".*/\1/')"
    if [ -z "$app_identity" ] || [ -z "$installer_identity" ]; then
        echo "Developer ID Application/Installer identity missing from imported keychain" >&2
        exit 1
    fi

    # The exact certificate (not merely one with the same name) that
    # ensure-macos-profiles.py binds the provisioning profiles to.
    local app_pem="$APP_CERT_FILE"
    security find-certificate -a -Z -p "$keychain" | awk -v h="$app_hash" '
        /^SHA-1 hash:/ { keep = ($3 == h) }
        keep && /-----BEGIN CERTIFICATE-----/ { on = 1 }
        keep && on { print }
        /-----END CERTIFICATE-----/ { on = 0 }' > "$app_pem"
    grep -q 'BEGIN CERTIFICATE' "$app_pem" || { echo "could not export the Developer ID Application certificate" >&2; exit 1; }

    {
        echo "SIGNING_KEYCHAIN=$keychain"
        echo "NOTARY_KEY_PATH=$notary_key"
        echo "APP_SIGN_IDENTITY=$app_identity"
        echo "PKG_SIGN_IDENTITY=$installer_identity"
        echo "APP_CERT_PEM=$app_pem"
        echo "PROFILE_STATE=$PROFILE_STATE"
    } >> "$GITHUB_ENV"
}

profiles() {
    : "${GITHUB_ENV:?GITHUB_ENV must be set}"
    case "${PROFILE_SOURCE:-api}" in
        api)
            python3 "$ENSURE_PROFILES" ensure \
                --key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID" \
                --cert-pem "$APP_CERT_PEM" --state "$PROFILE_STATE" --env-out "$PROFILES_ENV"
            cat "$PROFILES_ENV" >> "$GITHUB_ENV"
            ;;
        xcode-experiment)
            echo "Provisioning profiles: left to Xcode (-allowProvisioningUpdates with the App Store Connect key)."
            ;;
        *)
            echo "Unknown profile source '${PROFILE_SOURCE}': use api or xcode-experiment." >&2
            exit 1
            ;;
    esac
}

teardown() {
    set +e
    python3 "$ENSURE_PROFILES" cleanup --state "$PROFILE_STATE"
    # Only the files setup writes; the keychain is deleted even if setup died
    # before exporting its path.
    security delete-keychain "$KEYCHAIN" 2>/dev/null
    rm -f "$NOTARY_KEY_FILE" "$APP_CERT_FILE" "$PROFILES_ENV" "$APP_P12" "$INSTALLER_P12"
    return 0
}

case "${1:-}" in
    setup) setup ;;
    profiles) profiles ;;
    teardown) teardown ;;
    *) echo "usage: $0 setup|profiles|teardown" >&2; exit 2 ;;
esac
