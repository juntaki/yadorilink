# YadoriLink

**Cloud-like file sync, without cloud file storage.**

[日本語 README](README.ja.md)

YadoriLink gives you accounts, devices, sharing, and permissions while
keeping file contents on your own devices.

Files sync directly between authorized peers.
YadoriLink coordinates them, but does not store your files.

> Pre-1.0 — under active development.

## What it does

- Direct encrypted sync between your devices
- Account-based sharing, permissions, and revocation
- Versions, conflicts, and on-demand storage

Runs on macOS 14+ (Apple silicon only), Windows, and Linux.

## Install

Download the installer for your platform from
[GitHub Releases](https://github.com/juntaki/yadorilink/releases):

| Platform | Download |
|---|---|
| macOS | `yadorilink-macos.pkg` (signed and notarized) |
| Windows | `yadorilink-setup-unsigned.exe` (currently unsigned, see below) |
| Linux (Debian/Ubuntu) | `yadorilink-linux-amd64.deb` |

Each file has a `.sha256` checksum next to it.

**Windows:** the installer is currently not code-signed, so Windows
SmartScreen shows an "unknown publisher" warning. Compare the SHA-256 of
the download with the published `.sha256` before choosing "Run anyway".

**Windows, long-offline devices:** a Windows device that was offline so long
that it can no longer catch up, and would need its synced history rebuilt,
is not supported yet. YadoriLink refuses to start the rebuild (the log says
"rebootstrap is blocked") and leaves the folder as it was. Devices that stay
reasonably in sync are not affected.

Install steps, first run, updates, and uninstalling are in the platform READMEs:
[macOS](platforms/macos/package/README.md), [Windows](platforms/windows/package/README.md),
[Linux](platforms/linux/package/README.md).

Release builds connect to the YadoriLink coordination service
automatically. To use a different coordination service, set
`YADORILINK_COORDINATION_ADDR` (for example
`YADORILINK_COORDINATION_ADDR=http://127.0.0.1:8787`) before running any
`yadorilink` command or the daemon.

## First run

1. Install and open YadoriLink. On macOS, open `YadoriLink.app`; on Windows,
   keep "Set up YadoriLink now" checked on the installer's last page.
2. Sign in with Google in your browser.
3. Choose the folder to sync. On macOS, review it and click "Link Folder".

Linux has no desktop app yet; use the command line below.

## Advanced / command line

The same setup is available from a terminal. The installers start the daemon
for you on macOS and Windows; on Linux run `systemctl --user enable --now
yadorilink-daemon`, then:

```bash
yadorilink login
yadorilink device register --name "my-device"
yadorilink share create my-share --path ~/some/folder
yadorilink status
```

`yadorilink status` and `yadorilink doctor` show what the daemon sees. When a
shared folder's history is rebuilt, YadoriLink keeps ("preserves") versions
or local changes it could not carry over instead of deleting them.
`yadorilink preserved list` shows them; `preserved restore <item-id>` writes
a kept version back as a new change, `retry <item-id>` re-submits one of your
own changes, and `discard <item-id>` deletes the item.

Add another of your devices:

```bash
yadorilink share joinable
yadorilink share join my-share --path ~/some/folder
```

Share with someone else:

```bash
yadorilink share invite my-share --role editor
# the recipient runs:
yadorilink share accept <code> --path ~/some/folder
```

## Updating and resetting (pre-1.0)

Update every device to the same release. Pre-1.0 releases do not promise
compatibility migrations between versions. If a version incompatibility
prevents startup, remove YadoriLink's local application state and
credentials and set up again; your synced folders and their files are not
deleted. The macOS, Windows, and Linux READMEs list where that state lives.

## How it works

YadoriLink separates management from storage.

The coordination service handles accounts, device identity, sharing,
permissions, and connectivity. File contents stay on user devices and move
only between authorized peers.

## Build from source

For development, or if you prefer to build it yourself:

```bash
cargo build --workspace --release
./target/release/yadorilink --help
```

Without a build-time setting, a source build connects to
`http://127.0.0.1:8787` unless `YADORILINK_COORDINATION_ADDR` is set.
Release builds are compiled with `YADORILINK_DEFAULT_COORDINATION_ADDR`
set to the production coordination service; you can set the same variable
when you build to bake in your own default. Resolution order at run time:
`YADORILINK_COORDINATION_ADDR`, then the compiled default, then
`http://127.0.0.1:8787`. Start the daemon yourself with
`yadorilink daemon start`.

## Development

YadoriLink is written primarily in Rust.

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Main components:

- `crates/yadorilink-daemon` — sync daemon
- `crates/yadorilink-cli` — command-line interface
- `crates/yadorilink-transport` — peer connectivity
- `crates/yadorilink-desktop-app` — desktop app
- `platforms/macos/app` — Finder integration
- `platforms/windows/shell` — Explorer integration

Platform packaging details are in the READMEs under
[`platforms/`](platforms/).

## Security

See [SECURITY.md](.github/SECURITY.md).

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md).

## License

Licensed under the [GNU Affero General Public License v3.0 only](LICENSE)
(AGPL-3.0-only).

The hosted coordination service at `control.yadori.link` is governed by the
[Privacy Policy](https://yadori.link/privacy/) and the
[Terms of Service](https://yadori.link/terms/).
