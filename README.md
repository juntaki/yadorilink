# YadoriLink

**A local-first, peer-to-peer folder sync tool for people who want Dropbox-like
convenience without storing file contents on a central server.**

[Why YadoriLink?](#why-yadorilink) ·
[How is this different?](#how-is-this-different) ·
[Status](#status) ·
[Quick start](#quick-start) ·
[Building from source](#building-from-source) ·
[日本語](README.ja.md)

YadoriLink keeps folders in sync across your devices and shared groups. File
contents move directly between devices over an authenticated, encrypted
transport. A coordination service manages accounts, device identities, and
share membership only — it never sees, stores, or transits your file contents.

## Why YadoriLink?

- **Peer-to-peer by default** — file contents move directly between devices
  when a direct connection is possible; a relay is only a fallback for when
  it isn't.
- **Content-blind coordination** — the coordination plane's job is accounts,
  device identities, and share membership, nothing else. It is designed so
  that it never receives plaintext file contents. (This design has not yet
  had an independent third-party audit — see [SECURITY.md](SECURITY.md).)
- **Cross-platform from one codebase** — the CLI, daemon, and sync engine are
  a single Rust workspace targeting Linux, Windows, and macOS.
- **CLI-first, daemon-backed** — scriptable and automatable, a natural fit for
  self-hosters and power users, not just point-and-click desktop use.
- **Open source client** — every line that touches your files, your keys, and
  the wire protocol is here to read, build, and audit yourself.

## How is this different?

Peer-to-peer sync isn't new — Syncthing and Resilio Sync already do
folder-to-folder replication with no cloud storage of file contents, and
Dropbox already does frictionless account/share management with cloud
storage. YadoriLink aims at the combination:

- Dropbox-like accounts, device identity, and share membership management
- Syncthing/Resilio-style direct peer-to-peer file transfer, not
  store-and-forward through a server
- an inspectable, open-source Rust implementation of the sync/transport/
  encryption stack
- an optional relay for when direct connectivity isn't possible, designed so
  it never has access to plaintext file contents it forwards

## Status

YadoriLink is pre-1.0 and under active development. Concretely, today:

- **CLI + daemon** (`yadorilink`, `yadorilink-daemon`) are the primary,
  most-exercised interface — this is where to start.
- **Desktop status app** (`yadorilink-status-app`) is a lightweight, read-only
  status viewer, not a full GUI onboarding/management experience yet.
- **macOS Finder/File Provider integration** works but needs a real Apple
  Developer signing identity to run under App Sandbox — CI only publishes
  unsigned raw binaries, not the packaged `.pkg` (see
  [`installer/macos/README.md`](installer/macos/README.md)).
- **Windows Explorer shell extension** builds and runs on x86_64; `arm64`
  support across the project is untested and should be treated as
  experimental.
- **Coordination service**: this repository currently focuses on the client,
  sync engine, transport, relay, installers, and shell integrations. A
  complete end-to-end deployment also needs a coordination service for
  accounts, device identities, and share membership. A public hosted
  coordination service is not available yet, so an end-to-end sync setup
  isn't runnable purely from a clone of this repo today. If you want to
  self-host or need a hosted option, please open an issue.

## Quick start

What you can do with just this repository today — build the client and look
around:

```bash
cargo build --workspace --release
./target/release/yadorilink --help
```

The full first-run flow, once you have access to a coordination service (see
[Status](#status) above):

```bash
yadorilink login
yadorilink device register --name "my-device"
yadorilink share create my-share
yadorilink link ~/some/folder my-share
yadorilink status
```

Platform-specific installer behavior, shell integration, and verification
steps live in the install docs linked below.

## Install

### Latest Development Build

Prebuilt development builds are published on GitHub Releases:

https://github.com/juntaki/yadorilink/releases/tag/nightly

- Linux: `.deb` package or binary tarball
- Windows: unsigned installer or binary zip
- macOS: unsigned binary tarball

YadoriLink is pre-1.0. These builds are for testing and early feedback.
Windows builds are unsigned, so SmartScreen warnings are expected. macOS
builds are unsigned and not notarized.

Direct links:

- Linux `.deb`: <https://github.com/juntaki/yadorilink/releases/download/nightly/yadorilink-linux-amd64.deb>
- Windows installer: <https://github.com/juntaki/yadorilink/releases/download/nightly/yadorilink-setup.exe>
- macOS tarball: <https://github.com/juntaki/yadorilink/releases/download/nightly/yadorilink-macos.tar.gz>

### Development Artifacts

GitHub Actions artifacts are mainly for maintainers and testers. They are CI
outputs with limited retention, not the primary download channel for ordinary
users. For ordinary downloads, use GitHub Releases instead.

The CI workflow still publishes per-run artifacts:

- `yadorilink-linux-artifacts`: a `.deb` package plus a Linux binary tarball
- `yadorilink-windows-artifacts`: an unsigned `yadorilink-setup.exe` plus a
  Windows binary zip
- `yadorilink-macos-artifacts`: a macOS binary tarball

Notes:

- Linux artifacts include `SHA256SUMS` plus the `.deb.sha256` sidecar.
- Windows artifacts include `SHA256SUMS` plus the installer's `.sha256`
  sidecar. CI builds are unsigned, so SmartScreen warnings are expected.
- macOS CI publishes raw binaries only. Building a signed `.pkg` still
  requires a signing-capable Mac and a notarization flow outside Actions.

### Platform install/packaging docs

- Linux package build/install: [`installer/linux/README.md`](installer/linux/README.md)
- Windows packaging: [`installer/windows/README.md`](installer/windows/README.md)
- macOS packaging: [`installer/macos/README.md`](installer/macos/README.md)

## Repository contents

| Path | Purpose |
|---|---|
| `crates/yadorilink-cli` | User-facing CLI (`yadorilink`) |
| `crates/yadorilink-daemon` | Background sync daemon (`yadorilink-daemon`) |
| `crates/yadorilink-transport` | Peer transport plus relay server (`yadorilink-relay`) |
| `crates/yadorilink-sync-core` | Sync engine and reconciliation logic |
| `crates/yadorilink-local-storage` | Local block store |
| `crates/yadorilink-ipc-proto` | Shared protobuf and wire-format definitions |
| `crates/yadorilink-desktop-app` | Desktop status app (`yadorilink-status-app`) |
| `shell-ext/windows` | Explorer shell extension and CfAPI host |
| `shell-ext/macos` | Finder/File Provider integration |

## Building from source

### Core workspace

On macOS and Windows:

```bash
cargo build --workspace --release
```

On Linux, the desktop status app is not part of the supported packaging flow,
so build the shipped binaries like this:

```bash
cargo build --workspace --release --exclude yadorilink-desktop-app
```

### Tests and checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

On Linux, mirror CI by excluding the desktop app:

```bash
cargo clippy --workspace --exclude yadorilink-desktop-app --all-targets -- -D warnings
cargo test --workspace --exclude yadorilink-desktop-app
```

### Platform packaging

Linux:

```bash
./installer/linux/build-deb.sh
```

Windows:

```powershell
cargo build --workspace --release
cd shell-ext\windows
cargo build --release
cd ..\..
powershell -ExecutionPolicy Bypass -File installer\windows\build-installer.ps1
```

macOS:

```bash
./installer/macos/build-pkg.sh
```

## Security

YadoriLink is pre-1.0, and its cryptographic design has not had an
independent third-party audit — review the source yourself before relying
on it for sensitive data. See [SECURITY.md](SECURITY.md) for how to report
a vulnerability.

## Contributing

Issues and pull requests are welcome. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR, and report
vulnerabilities privately through [SECURITY.md](SECURITY.md) instead of a
public issue.

## License

YadoriLink is dual-licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
