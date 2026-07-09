# Contributing to YadoriLink

Thanks for taking the time to improve YadoriLink. The project is pre-1.0, so
interfaces and workflows can still change quickly, but small, focused issues
and pull requests are welcome.

## Before Opening an Issue

- Search existing issues first.
- Do not include credentials, tokens, private keys, recovery codes, account
  IDs, device IDs, or private file contents.
- Report security vulnerabilities by email as described in
  [SECURITY.md](SECURITY.md), not in a public issue.
- For diagnostics, prefer the built-in report export flow and review the
  exported JSON before sharing it.

## Development Setup

Install a stable Rust toolchain and Protocol Buffers compiler, then run:

```bash
cargo build --workspace
cargo test --workspace
```

On Linux, the desktop status app is excluded from the supported packaging flow:

```bash
cargo build --workspace --exclude yadorilink-desktop-app
cargo test --workspace --exclude yadorilink-desktop-app
```

## Checks Before a Pull Request

Run the checks that match the area you changed:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

For platform-specific shell extensions:

```bash
cd shell-ext/windows
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo build --release
```

```bash
cd shell-ext/macos/core
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo build --release
```

## Pull Request Guidelines

- Keep PRs focused on one behavior or documentation change.
- Include tests when changing sync, transport, persistence, IPC, or security
  relevant behavior.
- Document user-visible CLI or installer changes.
- Explain any intentionally skipped platform check in the PR description.
- Do not add new network submission, telemetry, credential handling, or
  key-handling behavior without calling it out explicitly.

## Licensing

By contributing, you agree that your contribution is licensed under the same
dual MIT or Apache-2.0 terms as the project.
