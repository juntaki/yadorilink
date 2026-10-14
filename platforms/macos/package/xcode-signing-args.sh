#!/bin/bash
#
# platforms/macos/package/xcode-signing-args.sh
#
# Sourced by build-pkg.sh. Defines xcode_signing_args, which fills the
# XCODE_SIGNING_ARGS array with the signing arguments for the xcodebuild of
# YadoriLink.app. Kept apart so xcode-signing-args.test.sh can check each mode
# without running a build.
#
# Development (YADORILINK_RELEASE_BUILD unset): Automatic signing, as
# project.yml says, with -allowProvisioningUpdates.
#
# Release (YADORILINK_RELEASE_BUILD=1), default: Manual Developer ID
# Application signing with a secure timestamp. The two extensions are the only
# targets that declare a restricted entitlement (the App Group), so they are
# the only ones given a provisioning profile, by the variables
# YADORILINK_FINDERSYNC_PROFILE / YADORILINK_FILEPROVIDER_PROFILE (profile UUID
# or name; project.yml turns them into per-target PROVISIONING_PROFILE_SPECIFIER).
# The host app is signed with no profile. No -allowProvisioningUpdates: the
# build must not depend on an Xcode account.
#
# Release with YADORILINK_XCODE_PROFILE_EXPERIMENT=1: an experiment, not the
# default. Instead of installed profiles, let Xcode create the Developer ID
# profiles itself (-allowProvisioningUpdates) authenticated with the App Store
# Connect API key given as YADORILINK_NOTARY_KEY / _KEY_ID / _ISSUER. Whether
# Xcode then picks the right profiles on a clean runner is exactly what the
# experiment tests; the built extensions' embedded profiles are validated
# afterwards either way.
#
# Reads: YADORILINK_RELEASE_BUILD, YADORILINK_APP_SIGN_IDENTITY,
# YADORILINK_XCODE_PROFILE_EXPERIMENT, and the profile and
# notary variables above. Returns non-zero with a message when a required
# value is missing.

# shellcheck disable=SC2034  # XCODE_SIGNING_ARGS is read by the sourcing script
xcode_signing_args() {
    XCODE_SIGNING_ARGS=()
    if [ "${YADORILINK_RELEASE_BUILD:-0}" != "1" ]; then
        XCODE_SIGNING_ARGS=(-allowProvisioningUpdates)
        return 0
    fi

    local identity="${YADORILINK_APP_SIGN_IDENTITY:-}"
    if [ -z "$identity" ]; then
        echo "A release xcodebuild requires YADORILINK_APP_SIGN_IDENTITY." >&2
        return 1
    fi

    if [ "${YADORILINK_XCODE_PROFILE_EXPERIMENT:-0}" = "1" ]; then
        if [ -z "${YADORILINK_NOTARY_KEY:-}" ] || [ -z "${YADORILINK_NOTARY_KEY_ID:-}" ] \
            || [ -z "${YADORILINK_NOTARY_ISSUER:-}" ]; then
            echo "YADORILINK_XCODE_PROFILE_EXPERIMENT=1 needs YADORILINK_NOTARY_KEY, _KEY_ID and _ISSUER." >&2
            return 1
        fi
        XCODE_SIGNING_ARGS=(
            CODE_SIGN_IDENTITY="$identity"
            OTHER_CODE_SIGN_FLAGS=--timestamp
            -allowProvisioningUpdates
            -authenticationKeyPath "$YADORILINK_NOTARY_KEY"
            -authenticationKeyID "$YADORILINK_NOTARY_KEY_ID"
            -authenticationKeyIssuerID "$YADORILINK_NOTARY_ISSUER"
        )
        return 0
    fi

    if [ -z "${YADORILINK_FINDERSYNC_PROFILE:-}" ] || [ -z "${YADORILINK_FILEPROVIDER_PROFILE:-}" ]; then
        echo "A release xcodebuild requires YADORILINK_FINDERSYNC_PROFILE and" >&2
        echo "YADORILINK_FILEPROVIDER_PROFILE (installed Developer ID profile UUIDs or names)." >&2
        return 1
    fi
    XCODE_SIGNING_ARGS=(
        CODE_SIGN_STYLE=Manual
        CODE_SIGN_IDENTITY="$identity"
        OTHER_CODE_SIGN_FLAGS=--timestamp
        YADORILINK_FINDERSYNC_PROFILE="$YADORILINK_FINDERSYNC_PROFILE"
        YADORILINK_FILEPROVIDER_PROFILE="$YADORILINK_FILEPROVIDER_PROFILE"
    )
}
