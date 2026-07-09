# YadoriLink macOS installer

Builds a macOS `.pkg` that installs:

| Payload | Installed to |
|---|---|
| `yadorilink` (CLI) | `/usr/local/bin/yadorilink` |
| `yadorilink-daemon` | `/usr/local/bin/yadorilink-daemon` |
| `YadoriLinkFinderSyncHost.app` (FinderSync + File Provider extensions) | `/Applications/YadoriLinkFinderSyncHost.app` |

The relay and any coordination-service deployment are server-side components and
are **not** installed by this desktop/client package.

This file covers building, signing, verifying, and uninstalling the `.pkg`.

## Building

```bash
./build-pkg.sh
```

Requires, on the build machine:
- Xcode (for `xcodebuild`) and `xcodegen` (`brew install xcodegen`, or a
  release binary on `$PATH`/in `~/xcodegen-bin/`)
- A real "Apple Development" or "Apple Distribution" codesigning identity
  in the login keychain (`security find-identity -v -p codesigning`) —
  see "Signing and notarization" below
- Rust/cargo, for `cargo build --workspace --release`

Output: `dist/yadorilink-<version>-unsigned.pkg` plus a `.sha256` sidecar for
local/interim unsigned builds (version comes from the workspace's
`Cargo.toml`).

The script also leaves a component-only package at
`dist/YadoriLinkComponent.pkg` (the actual payload + scripts) — the
distribution package (`yadorilink-*.pkg` or `yadorilink-*-unsigned.pkg`) is a
`productbuild` wrapper around it, mainly so Installer.app shows "yadorilink"
as the product title.

`.stage/` and `.xcode-build/` are scratch directories the script rebuilds
from scratch every run; safe to delete between builds.

## Signing and notarization

Release builds must sign the outer `.pkg` with a Developer ID Installer
identity:

```bash
YADORILINK_RELEASE_BUILD=1 \
YADORILINK_PKG_SIGN_IDENTITY="Developer ID Installer: Example, Inc. (TEAMID)" \
YADORILINK_NOTARY_PROFILE=yadorilink-notary \
  ./build-pkg.sh
```

When `YADORILINK_PKG_SIGN_IDENTITY` is set, the script runs `productsign`,
optionally submits/staples through `xcrun notarytool` when
`YADORILINK_NOTARY_PROFILE` is set, then verifies the result with
`pkgutil --check-signature` and `spctl -a -vvv -t install`.

Local/interim unsigned builds are still possible by omitting
`YADORILINK_RELEASE_BUILD=1`; the script writes
`dist/yadorilink-<version>-unsigned.pkg.sha256` next to the package. Opening
an unsigned package will show Gatekeeper's "unidentified developer" warning;
that's expected for local unsigned builds. Use Finder's right-click Open flow
if you need to run an unsigned local build.

The `YadoriLinkFinderSyncHost.app` bundled *inside* the pkg, however, is
built with Xcode's automatic signing using a real "Apple Development"/
"Apple Distribution" identity (`project.yml`: `CODE_SIGN_STYLE: Automatic`,
`DEVELOPMENT_TEAM: 594UQF7QX3`) — deliberately, not by oversight. This
repo's own build history (see
`shell-ext/macos/YadoriLinkFinderSync/Extension/Extension.entitlements`'s doc
comment) already proved that an **ad-hoc-signed** (`codesign --sign -`)
build of this exact FinderSync/File Provider extension pair does not
actually launch under App Sandbox: PlugInKit discovers it fine, but the
sandboxed process dies silently right after `AppSandbox` init, before any
of the extension's own code runs. Shipping an ad-hoc-signed `.app` inside
any installer would therefore produce something that visibly doesn't work
at all. If you build this on a machine with no such identity available,
`xcodebuild` will fail with a signing error rather than silently falling
back to ad-hoc.

## What the installer does beyond copying files

`scripts/preinstall` and `scripts/postinstall` (bundled into the
component `.pkg` via `pkgbuild --scripts`) run as root during install and:

1. Determine the actual GUI-logged-in ("console") user — **not** root,
   which is who a `postinstall` script normally runs as, and **not**
   whichever user happens to own `$HOME` in that root context. This uses
   `stat -f%Su /dev/console` (with a `who`-based fallback), the standard
   trick for finding the real target user from a root-run installer
   script.
2. Write `~/Library/LaunchAgents/com.yadorilink.daemon.plist` for that user
   (a **LaunchAgent**, not a LaunchDaemon — the daemon needs the
   interactive user's Keychain session for the access/refresh tokens
   `yadorilink login` stores there) and load it into that user's GUI launchd
   domain via `launchctl asuser <uid> launchctl bootstrap gui/<uid> ...`
   (the modern replacement for the deprecated `launchctl load`, and the
   only way to reach a *specific* user's session from a root process).
   The agent sets `YADORILINK_SHELL_IPC_SOCKET` to the daemon's App Group
   container path (`~/Library/Group Containers/group.com.juntaki.yadorilink.shared/
   shell.sock`) so the sandboxed FinderSync/File Provider extensions can
   actually reach it — the daemon's *default* socket path
   (`~/Library/Application Support/yadorilink/shell.sock`) is not reachable
   from inside the App Sandbox.
3. Register the two extensions with PlugInKit (`pluginkit -a`, `pluginkit
   -e use`) and launch the host app once, hidden, so
   `DomainRegistration.swift` can register any already-known OnDemand
   File Provider domains. This does **not** flip the user-visible enable
   toggle — Apple provides no supported API for that; the user still
   needs to enable "yadorilink FinderSync" / the File Provider domain in
   System Settings > General > Login Items & Extensions, same as the
   host app's own in-window instructions say.

`uninstall.sh` is a companion script (not run automatically by the
installer — macOS `.pkg` has no built-in uninstaller) that reverses all
of the above; see its header comment.

## Files

- `build-pkg.sh` — builds everything and produces the final `.pkg`
- `Distribution.xml` — `productbuild` distribution definition (product
  title, single component choice)
- `scripts/preinstall`, `scripts/postinstall` — component pkg scripts
- `uninstall.sh` — companion uninstaller (run manually, with `sudo`)
