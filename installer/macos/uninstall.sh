#!/bin/bash
#
# installer/macos/uninstall.sh
#
# macOS .pkg installers have no built-in uninstaller — `installer(8)`
# only ever adds files and runs scripts; there is no matching "remove"
# verb, and pkgutil's receipt database only lets you list/forget what was
# installed, not remove it. This script is the companion "undo" for
# build-pkg.sh's installer, run manually.
#
# Run with sudo (it removes files under /usr/local/bin and /Applications,
# and unloads a LaunchAgent that must be reached via the console user's
# GUI launchd domain — see postinstall's comment on why root can't just
# `launchctl load/unload` a per-user LaunchAgent directly):
#
#   sudo ./uninstall.sh
#
# What this does NOT remove (deliberately — this is uninstalling the
# *application*, not the user's data):
#   - ~/Library/Application Support/yadorilink (sync state DB, block store,
#     WireGuard key, device.json)
#   - ~/Library/Group Containers/group.com.juntaki.yadorilink.shared (shell IPC
#     socket dir)
#   - Keychain items (service name "yadorilink") holding access/refresh
#     tokens
#   - Any linked folders' local content
# Pass --purge-data to also remove the first three (never removes your
# actual synced files).

set -uo pipefail

PURGE_DATA=0
if [ "${1:-}" = "--purge-data" ]; then
    PURGE_DATA=1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs to run as root (it removes /usr/local/bin and /Applications files)."
    echo "Re-run as: sudo $0 ${1:-}"
    exit 1
fi

log() { echo "[yadorilink uninstall] $*"; }

user_home_path_has_symlink_component() {
    local user_home="$1"
    local path="$2"
    case "$path" in
        "$user_home"/*) ;;
        *)
            log "Refusing to operate outside console user's home: $path"
            return 0
            ;;
    esac

    local rel="${path#"$user_home"/}"
    local current="$user_home"
    local component
    while [ -n "$rel" ]; do
        component="${rel%%/*}"
        current="$current/$component"
        if [ -L "$current" ]; then
            log "Refusing to follow symlink in user-writable uninstall path: $current"
            return 0
        fi
        if [ "$rel" = "$component" ]; then
            break
        fi
        rel="${rel#*/}"
    done
    return 1
}

safe_rm_user_file() {
    local user_home="$1"
    local path="$2"
    if user_home_path_has_symlink_component "$user_home" "$path"; then
        log "Skipped symlink-sensitive file removal: $path"
        return
    fi
    /bin/rm -f "$path"
}

safe_rm_user_dir() {
    local user_home="$1"
    local path="$2"
    if user_home_path_has_symlink_component "$user_home" "$path"; then
        log "Skipped symlink-sensitive directory removal: $path"
        return
    fi
    /bin/rm -rf "$path"
}

AGENT_LABEL="com.yadorilink.daemon"
APP_PATH="/Applications/YadoriLinkFinderSyncHost.app"
FINDER_SYNC_EXT_ID="com.juntaki.yadorilink.FinderSync"
FILE_PROVIDER_EXT_ID="com.juntaki.yadorilink.FileProvider"

CONSOLE_USER="$(/usr/bin/stat -f%Su /dev/console 2>/dev/null || true)"
if [ -z "$CONSOLE_USER" ] || [ "$CONSOLE_USER" = "root" ]; then
    CONSOLE_USER="$(/usr/bin/who 2>/dev/null | /usr/bin/awk '$2 == "console" { print $1; exit }')"
fi

if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ] && [ "$CONSOLE_USER" != "loginwindow" ]; then
    CONSOLE_UID="$(/usr/bin/id -u "$CONSOLE_USER" 2>/dev/null || true)"
    USER_HOME="$(/usr/bin/dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{print $2}')"

    if [ -n "$CONSOLE_UID" ]; then
        log "Stopping and unloading LaunchAgent for $CONSOLE_USER..."
        /bin/launchctl asuser "$CONSOLE_UID" /bin/launchctl bootout "gui/${CONSOLE_UID}/${AGENT_LABEL}" >/dev/null 2>&1 || true

        log "Removing PlugInKit registration for yadorilink extensions..."
        /usr/bin/sudo -u "$CONSOLE_USER" /usr/bin/pluginkit -r "$APP_PATH/Contents/PlugIns/YadoriLinkFinderSync.appex" >/dev/null 2>&1 || true
        /usr/bin/sudo -u "$CONSOLE_USER" /usr/bin/pluginkit -r "$APP_PATH/Contents/PlugIns/YadoriLinkFileProvider.appex" >/dev/null 2>&1 || true
        /usr/bin/sudo -u "$CONSOLE_USER" /usr/bin/pluginkit -e ignore -i "$FINDER_SYNC_EXT_ID" >/dev/null 2>&1 || true
        /usr/bin/sudo -u "$CONSOLE_USER" /usr/bin/pluginkit -e ignore -i "$FILE_PROVIDER_EXT_ID" >/dev/null 2>&1 || true
    fi

    if [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ]; then
        safe_rm_user_file "$USER_HOME" "$USER_HOME/Library/LaunchAgents/${AGENT_LABEL}.plist"
        log "Removed $USER_HOME/Library/LaunchAgents/${AGENT_LABEL}.plist"

        if [ "$PURGE_DATA" -eq 1 ]; then
            log "Purging data (--purge-data): sync state, blocks, device config, App Group socket dir..."
            safe_rm_user_dir "$USER_HOME" "$USER_HOME/Library/Application Support/yadorilink"
            safe_rm_user_dir "$USER_HOME" "$USER_HOME/Library/Group Containers/group.com.juntaki.yadorilink.shared"
            safe_rm_user_dir "$USER_HOME" "$USER_HOME/Library/Logs/yadorilink"
            /usr/bin/sudo -u "$CONSOLE_USER" /usr/bin/security delete-generic-password -s yadorilink "$USER_HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1 || true
        fi
    fi
else
    log "WARNING: no GUI console user detected; skipping LaunchAgent/PlugInKit cleanup."
    log "(remove ~/Library/LaunchAgents/${AGENT_LABEL}.plist by hand for any affected user)"
fi

log "Removing /usr/local/bin/yadorilink and /usr/local/bin/yadorilink-daemon..."
rm -f /usr/local/bin/yadorilink /usr/local/bin/yadorilink-daemon

log "Removing $APP_PATH..."
rm -rf "$APP_PATH"

log "Forgetting pkg receipt (com.yadorilink.installer.component), if present..."
pkgutil --forget com.yadorilink.installer.component >/dev/null 2>&1 || true

log "Uninstall complete."
if [ "$PURGE_DATA" -eq 0 ]; then
    log "User data under ~/Library/Application Support/yadorilink was left in place."
    log "Re-run with --purge-data to remove it too."
fi
