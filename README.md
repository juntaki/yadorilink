# YadoriLink

**A local-first, peer-to-peer folder sync tool that keeps file contents off
central storage.**

[Why YadoriLink?](#why-yadorilink) ·
[How is this different?](#how-is-this-different) ·
[What it does today](#what-it-does-today) ·
[Status](#status) ·
[Quick start](#quick-start) ·
[Building from source](#building-from-source) ·
[日本語](README.ja.md)

YadoriLink keeps folders in sync across your devices and shared groups. File
contents move directly between devices over an authenticated, encrypted
transport. A coordination service manages accounts, device identities, and
share membership only — it never sees, stores, or transits your file contents.

## Why YadoriLink?

- **Peer-to-peer, with no operator data path** — file contents move directly
  between devices. No YadoriLink-operated server or service ever forwards your
  data, so the project never carries — or pays to carry — your file traffic. To
  make direct connections work across home and mobile NATs, the transport
  tries IPv6, STUN-based address discovery, and router port mapping. If
  direct connectivity still isn't possible, an
  explicitly opted-in device you already trust and share with can relay your
  encrypted peer traffic for you (off by default; the relaying device forwards
  encrypted bytes only, it does not decrypt them) — a peer with no such device
  available is shown as "cannot connect" with the reason, instead of being
  silently routed through a middlebox it never agreed to.
- **Content-blind coordination** — the coordination plane's job is accounts,
  device identities, and share membership, nothing else. It is designed so
  that it never receives plaintext file contents.
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
- deliberately no operator-run data plane: when two devices can't reach each
  other directly, any other device that already holds the data can carry it
  between them over time (store-and-forward between authorized peers), so a
  shared group still converges without anyone operating a data plane

## What it does today

Beyond keeping two folders in step:

- **Sharing with real roles.** `share invite <group>` mints a one-use
  invite for a folder group you own and prints it three ways — a code, a
  `yadorilink://` URL, and a QR code drawn in the terminal — at either
  `viewer` (read-only) or `editor`, expiring in 7 days unless `--ttl-secs`
  says otherwise. The role is enforced by the receiving daemon, not just by
  the UI: a change signed by a viewer-role device is rejected on arrival. `--require-approval` turns redeeming the
  invite into a request that grants nothing until you run `share approve`
  (or turn it down with `share deny`); `share pending` lists who is
  waiting. `share members` is the "people with access" listing,
  `share change-role` moves an existing member between viewer and editor
  in place — no revoke-and-re-invite — and `share revoke` takes access
  away. Both downgrades and revocations reach a currently-connected peer
  promptly rather than on its next poll. For another device on your own
  account, `share grant` / `share joinable` / `share join` do the same job
  without an invite.
- **Selective sync.** Link a folder `--on-demand` and its files arrive as
  placeholders, fetched on first access, with an optional
  `--max-local-size` cap driving automatic eviction. `pin`, `unpin`,
  `evict`, and `materialization-status` control individual files;
  `share set-storage-mode` switches a whole folder between `eager` and
  `on-demand`. Because there is no central copy, giving up the last full
  replica is refused until another device is confirmed to hold every file.
- **Version history, trash, and conflicts.** `versions <file>` lists every
  retained version and `restore` brings one back as a new current version;
  a deleted file stays recoverable with `trash list` / `trash restore`.
  Retention is a fixed built-in policy applied to every link, with
  nothing per-link to configure: a superseded version is kept while it
  is *either* among the 10 most recent *or* less than 30 days old, and
  is expired only once it is neither — not whichever bound comes first.
  Simultaneous edits become conflicted copies rather than a silently lost
  write, listed by `conflicts list`.
- **Folder Rewind, as a preview.** `rewind <group> --at 2h` (or `--at 7d`,
  or a unix-nanosecond timestamp) prints what restoring the whole folder
  to that point in time would change, per action or per path with
  `--verbose`. Read-only: it shows the plan and applies nothing.
- **One-shot send.** `send <path> <device>` pushes a file or directory
  straight to another device on your account without linking or syncing
  anything. The other side lists what arrived with `inbox` and takes it
  with `receive`, which resumes if it was interrupted.
- **LAN peer discovery.** A peer the coordination plane has already told
  this device about is also found directly on the local network: a
  protobuf announcement sent every 30 seconds to the IPv4 broadcast
  address and to `224.0.0.251`, both on UDP port 31027. This is *not*
  mDNS/DNS-SD — nothing running Bonjour or Avahi will see these packets
  — and it is IPv4-only. Announcements are matched against the peer list
  as a whole, not per folder group. Once that list has arrived,
  reconnecting over the LAN takes no coordination round-trip, so LAN
  peers keep finding each other through a coordination-plane outage. It
  is not independent of the coordination plane, though: the peer list is
  not cached across restarts, so a cold start that has never reached the
  coordination plane discovers nothing.
- **A localhost REST + SSE API and web dashboard**, served by the daemon
  itself — see [below](#http-api-and-web-dashboard).
- **Operational tooling.** `doctor` (connectivity diagnosis by category),
  `connections` (recent connection attempts and why each one failed),
  `limits set` (bandwidth caps applied to the running daemon without a
  restart), `ignore list` / `test` / `explain`, `diagnose export` (a
  redacted support bundle), `backup export` / `import`, `account export`
  and self-service `account delete`, and `update check`, which fetches
  the release manifest, verifies its publisher signature, and reports
  whether a newer build applies to this platform and channel.

Not shipped yet, so the list above isn't read for more than it says:

- **Owner as a role you can hand out.** A folder group has exactly one
  owning account, and every management action — inviting, approving,
  revoking, changing a role — is that account's alone. `--role owner` is
  not accepted by any command, and ownership cannot be transferred.
- **Installing an update from inside the app.** `update check` works, but
  nothing downstream of it is wired up: no shipped build ever downloads
  the artifact, so there is never a verified artifact to hand a platform
  installer. Both `update install` and the tray's "Install Update" fail
  closed every time ("no verified update is ready to install"). Update by
  reinstalling from your package manager or from GitHub Releases.
- **Reusable share links.** Every invite is single-use; sharing with five
  people means minting five invites.
- **Applying a rewind.** `rewind` previews; there is no flag that makes it
  restore.
- **Mobile clients.** Linux, macOS, and Windows only.

## Status

YadoriLink is pre-1.0 and under active development. Concretely, today:

- **CLI + daemon** (`yadorilink`, `yadorilink-daemon`) are the primary,
  most-exercised interface — this is where to start.
- **Desktop app** (`yadorilink-status-app`) is a macOS menu-bar /
  Windows notification-area tray app, not shipped for Linux. It runs the
  first-run setup wizard (Google sign-in, device registration, creating a
  folder group, picking the first folder — redeeming an invite from
  another account is not part of it), shows live status, and opens two
  per-folder windows. The Details window shows that folder's status,
  conflicts, trash, and per-file version history, and acts on them:
  restore from trash, restore a version, and pin, unpin, hydrate, or
  evict an individual file — evict turns a local file back into a
  placeholder. The Share window mints invites (role, expiry,
  require-approval) and hands them over as a link, a QR code, or an email,
  lists who already has access, changes a member's role, approves or
  denies waiting requests, and revokes access. The tray itself also covers
  add/remove folder (picking from the groups your account already has),
  pause/resume, bandwidth presets, update checks, diagnostics export, and
  account management. Apart from the start-at-login toggle, everything it
  can do the CLI can do too — and the CLI does a good deal more.
- **HTTP API and web dashboard**, served by the daemon itself (see below),
  covers the status surface plus pause/resume, pin/unpin, evict, and
  restore — aimed at headless/NAS installs with no desktop.
- **macOS Finder/File Provider integration** works but needs a real Apple
  Developer signing identity to run under App Sandbox — CI only publishes
  unsigned raw binaries, not the packaged `.pkg` (see
  [`installer/macos/README.md`](installer/macos/README.md)).
- **Windows Explorer shell extension** builds and runs on x86_64; `arm64`
  support across the project is untested and should be treated as
  experimental.
- **Hosted coordination** is live at <https://yadorilink.juntaki.com>,
  currently in an early-tester phase. This repository remains the place to
  review the client/sync/transport code, build the tools, and try the local
  CLI/daemon surfaces.

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
yadorilink daemon start          # installers can also run it as a service
yadorilink login
yadorilink device register --name "my-device"
yadorilink share create my-share --path ~/some/folder
yadorilink status
```

`share create` creates the folder group and links the local folder in one
step — the creating device is the group's first full copy, so a local folder
has to exist before the group is advertised.

To bring in a second device on the same account, list what it can join and
join one:

```bash
yadorilink share joinable
yadorilink share join my-share --path ~/some/folder --storage-mode on-demand
```

To share with a different account, mint a one-use invite and let them redeem
it:

```bash
yadorilink share invite my-share --role editor        # prints a code, URL, and QR
yadorilink share accept <code-or-url> --path ~/their/folder
```

Platform-specific installer behavior, shell integration, and verification
steps live in the install docs linked below.

## HTTP API and web dashboard

Every `yadorilink-daemon` also serves a small dashboard over HTTP — useful
for a headless Linux box or NAS with no desktop, where the only other way to
see sync status is SSH plus the CLI. It is read-mostly: status, links,
conflicts, connections, versions, and materialization, plus the
`/api/events` Server-Sent-Events stream and a fixed set of actions
(pause/resume, pin/unpin, evict, restore) — and nothing else. Sharing,
linking, and account management are not exposed over HTTP at all.

By default it listens on `http://127.0.0.1:8484` (and `[::1]:8484` when IPv6
loopback is available). The daemon's startup log names the port and the path
of the token file it wrote (owner-read/write only, `0600`) -- never the token
value itself, since a log is often more widely readable or longer-retained
than that file. Read the token from that file:

```bash
cat <token_path>   # the path printed in the daemon's startup log
```

Open the dashboard URL in a browser and paste in that token. The same token
authenticates the REST endpoints under `/api/` (status, links, conflicts,
connections, versions, materialization, pause/resume, pin/unpin, evict,
restore) and the `/api/events` Server-Sent-Events stream.

Set `YADORILINK_HTTP_API_DISABLE` (to anything other than `0`/`false`) to
turn it off entirely, or `YADORILINK_HTTP_API_PORT` to change the port. For
running the dashboard's own frontend from a local dev server during
development, `YADORILINK_HTTP_API_DEV_ORIGIN` sets one extra exact `Origin`
to allow -- never set this in production.

**Trust model.** The daemon's control socket (the CLI's own channel to the
daemon) is a Unix domain socket gated by filesystem permissions — only the
owning OS user can connect to it at all. The HTTP dashboard sits on top of
that same control channel but listens on a loopback TCP port, which every
local user account (not just the daemon's owner) can attempt to connect to;
the bearer token is what keeps a request from succeeding. This is a
deliberate shift in trust boundary — from "gated by uid" to "gated by
possession of a token file only the owning uid can read" — so any local
user who can both reach the loopback port and read that token file has
full CLI-equivalent access to this daemon.

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

### Package managers

Once a package manager install is set up, it owns that install's updates —
YadoriLink's own built-in updater detects this at runtime and defers to
the package manager instead of racing it. No first tagged release has
been cut yet, so none of these are fully live — see each one's own
README for exact status.

- **macOS (Homebrew)**: `brew install --cask juntaki/yadorilink/yadorilink`
  (CLI + daemon + Finder integration, the signed `.pkg`) or `brew install
  juntaki/yadorilink/yadorilink` (CLI + daemon only, built from source) —
  [`juntaki/homebrew-yadorilink`](https://github.com/juntaki/homebrew-yadorilink)
- **Linux (APT, Debian/Ubuntu)**: `curl -fsSL
  https://yadorilink.juntaki.com/apt/install.sh | sudo sh && sudo apt
  update && sudo apt install yadorilink` — see
  [`installer/linux/apt/README.md`](installer/linux/apt/README.md)
- **Windows (WinGet)**: manifest prepared, not yet submitted — see
  [`installer/windows/winget/README.md`](installer/windows/winget/README.md)
- **Docker**: `docker run ghcr.io/juntaki/yadorilink-daemon` (the sync
  daemon only, headless) — see
  [`installer/docker/README.md`](installer/docker/README.md)

### Platform install/packaging docs

- Linux package build/install: [`installer/linux/README.md`](installer/linux/README.md)
- Windows packaging: [`installer/windows/README.md`](installer/windows/README.md)
- macOS packaging: [`installer/macos/README.md`](installer/macos/README.md)
- Full package-manager distribution map: [`installer/PACKAGING.md`](installer/PACKAGING.md)

## Repository contents

| Path | Purpose |
|---|---|
| `crates/yadorilink-cli` | User-facing CLI (`yadorilink`) |
| `crates/yadorilink-daemon` | Background sync daemon (`yadorilink-daemon`) |
| `crates/yadorilink-transport` | Peer transport, NAT traversal, and connection management |
| `crates/yadorilink-local-storage` | Local block store |
| `crates/yadorilink-ipc-proto` | Shared protobuf and wire-format definitions |
| `crates/yadorilink-http-api` | Localhost HTTP/REST + SSE dashboard, served by the daemon |
| `crates/yadorilink-desktop-app` | Desktop tray app and its GUI windows (`yadorilink-status-app`) |
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

YadoriLink is pre-1.0 and under active development. See
[SECURITY.md](SECURITY.md) for how to report a vulnerability.

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
