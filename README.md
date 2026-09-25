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

Runs on macOS, Windows, and Linux.

## Try it

Build from source:

```bash
cargo build --workspace --release
./target/release/yadorilink --help
```

With access to a coordination service:

```bash
yadorilink daemon start
yadorilink login
yadorilink device register --name "my-device"
yadorilink share create my-share --path ~/some/folder
```

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

## How it works

YadoriLink separates management from storage.

The coordination service handles accounts, device identity, sharing,
permissions, and connectivity. File contents stay on user devices and move
only between authorized peers.

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
- `shell-ext/macos` — Finder integration
- `shell-ext/windows` — Explorer integration

Platform packaging and install details are in the READMEs under
[`installer/`](installer/).

## Security

See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.
