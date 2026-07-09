# YadoriLink Linux installer

Builds a `.deb` that installs:

| Payload | Installed to |
|---|---|
| `yadorilink` (CLI) | `/usr/bin/yadorilink` |
| `yadorilink-daemon` | `/usr/bin/yadorilink-daemon` |
| systemd `--user` service unit | `/usr/lib/systemd/user/yadorilink-daemon.service` |
| license texts | `/usr/share/doc/yadorilink/` |

This is a **CLI/daemon-only** package:
`yadorilink-desktop-app` (the tray/menu-bar status GUI, macOS/Windows only)
and a Linux file-manager shell integration are explicitly out of scope.
There is no GTK/appindicator dependency anywhere in this
package as a result. `yadorilink-coordination` and `yadorilink-relay` are
server-side binaries and, as on the other platforms' installers, are
**not** part of this package — deploy those to your own server instead.

## Packaging approach: hand-authored `control`/`postinst` + `dpkg-deb`, not `cargo-deb`

This
package goes with a hand-authored `debian/control` + `postinst`/`postrm`
pair built via `dpkg-deb` (this directory's `build-deb.sh`), **not**
`cargo-deb`, for three reasons:

1. **Consistency with this repo's existing installers.** Both
   `installer/macos` (`build-pkg.sh`, `Distribution.xml`, hand-written
   `scripts/preinstall`/`postinstall`) and `installer/windows`
   (`yadorilink.iss`, hand-written `daemon-task.ps1`) are hand-authored,
   heavily-commented shell/Pascal-script/PowerShell rather than driven by
   packaging-metadata-in-the-manifest tooling. A hand-authored `.deb`
   keeps that same pattern rather than introducing a fourth, different
   style of installer for the fourth platform.
2. **No changes to any crate's `Cargo.toml`.** `cargo-deb` reads its
   packaging metadata from a `[package.metadata.deb]` table in the binary
   crate's own `Cargo.toml` — meaning `crates/yadorilink-cli/Cargo.toml`
   and `crates/yadorilink-daemon/Cargo.toml` would need edits. Those are
   shared files other task groups of this same change (and unrelated
   future changes) may be actively editing; a self-contained
   `installer/linux/` that touches no crate manifest avoids that
   collision surface entirely. (`cargo-deb` itself is also not added as a
   dependency of any crate — it would only ever be a build-time tool —
   but the metadata-placement issue above applies regardless of
   dependency vs. dev-tool status.)
3. **This package is trivially simple.** Two binaries, one static unit
   file, and a handful of doc files — the templating/dependency-resolution
   `cargo-deb` automates isn't buying much here, and a plain `control` file
   is easier for a reader unfamiliar with `cargo-deb` to audit line by
   line, matching this repo's general preference (see the other two
   installers' READMEs) for scripts that are transparent about exactly
   what they do.

If a future change wants `cargo-deb` (e.g. once RPM/other formats such as
Fedora/openSUSE/Arch are being juggled too), it remains a reasonable
revisit — this decision is scoped to this first `.deb`, not a permanent
constraint.

## Prerequisites

- A Debian/Ubuntu-family Linux machine (or CI runner), matching this
  package's own `Depends: libc6` and its systemd-based baseline.
- Rust/cargo, for `cargo build --release`.
- `dpkg-deb`, for building the archive itself — part of the base `dpkg`
  package, present on essentially every Debian-family system already
  (`apt-get install dpkg-dev` if somehow missing, e.g. a minimal
  container image).
- Optionally `lintian`, for an extra structural lint pass
  (`apt-get install lintian`) — not required to build or install.

## Build

```bash
./build-deb.sh
```

This runs `cargo build --release --workspace --exclude yadorilink-desktop-app
--bin yadorilink --bin yadorilink-daemon` (explicitly excluding both the
desktop app and `yadorilink-daemon`'s second, maintainer-only
`yadorilink-sign-manifest` bin target — see that crate's `Cargo.toml`),
stages the payload under `.stage/` (rebuilt from scratch every run, safe
to delete between builds), and produces:

```
dist/yadorilink_<version>_<arch>.deb
dist/yadorilink_<version>_<arch>.deb.sha256
```

Version comes from the workspace's `Cargo.toml` (`[workspace.package]`);
architecture is auto-detected from `uname -m` (`amd64`/`arm64`). Override
either, or skip the `cargo build` step and package prebuilt binaries from
elsewhere:

```bash
PKG_VERSION=0.1.0 PKG_ARCH=arm64 ./build-deb.sh
YADORILINK_BIN_DIR=/path/to/target/release ./build-deb.sh
```

Only an `x86_64`/`amd64` build has actually been run through real Linux
CI/manual verification so far; `arm64` is untested and should be treated
as experimental until someone actually runs it there.

## Install

```bash
sudo dpkg -i dist/yadorilink_<version>_<arch>.deb
# or, to also resolve the libc6 dependency automatically if missing:
sudo apt install ./dist/yadorilink_<version>_<arch>.deb
```

The systemd `--user` unit is installed but **not** started or enabled
automatically (see `systemd/yadorilink-daemon.service`'s header comment
— a per-user unit generally shouldn't be silently enabled by a package
installed as root). After installing,
each user who wants the daemon running persistently runs, once:

```bash
systemctl --user enable --now yadorilink-daemon
```

Then, same as macOS/Windows: `yadorilink login`, `yadorilink link ...`,
`yadorilink status`, etc. — see the top-level README for CLI usage.

## What the package does beyond copying files

`debian/postinst` (installed as the package's `postinst`) only runs
`systemctl daemon-reload` (so a running system manager notices the new
unit file) and prints the `systemctl --user enable --now` reminder above
— it takes no other action, deliberately (see its own header comment for
why: it runs as root with no specific user session to target, unlike the
macOS postinstall's `launchctl asuser` trick which at least has a
"console user" to find).

`debian/postrm` similarly only prints a reminder on `remove`/`purge`: a
per-user systemd unit the user enabled themselves can't be reached by a
root-run `dpkg -r`/`apt remove` either, so if you enabled the unit,
disable it yourself first (or use `uninstall.sh`, which does this for
you in the right order).

## Uninstall

```bash
./uninstall.sh                # stop/disable the user unit, then remove the package
./uninstall.sh --purge-data   # also remove ~/.local/share/yadorilink
```

Run as your **normal user, without sudo** on the whole script — see
`uninstall.sh`'s header comment for why (`systemctl --user` always
targets the invoking user's own session; running the whole script under
sudo would silently disable nothing). It escalates via `sudo` internally
only for the actual package removal (`dpkg -r`).

## Manual verification

Once built (`./build-deb.sh`) on a real Debian/Ubuntu machine or VM:

```bash
./verify-deb.sh dist/yadorilink_<version>_<arch>.deb
```

This checks the checksum sidecar, the control file's `Package`/`Version`
fields, and that the payload contains `/usr/bin/yadorilink`,
`/usr/bin/yadorilink-daemon` (both executable), and
`/usr/lib/systemd/user/yadorilink-daemon.service` (not executable) —
without requiring root or actually installing anything. It also runs
`lintian` if installed.

Beyond that structural check, verify the real install end to end:

1. `sudo apt install ./dist/yadorilink_<version>_<arch>.deb`
2. Confirm both binaries run: `yadorilink --version`,
   `yadorilink-daemon --version` (or `--help`).
3. Confirm the unit file is present and well-formed:
   `systemctl --user cat yadorilink-daemon` (before enabling it, this
   just prints the unit's contents from the shipped file).
4. `systemctl --user enable --now yadorilink-daemon`, then
   `systemctl --user status yadorilink-daemon` and confirm it's
   `active (running)`.
5. Kill the daemon process directly (`pkill yadorilink-daemon`) and
   confirm systemd restarts it within a couple seconds
   (`Restart=on-failure`) — `journalctl --user -u yadorilink-daemon`
   should show the restart.
6. Run `yadorilink status` against the running daemon and confirm it
   reaches it over the Unix-domain-socket control transport (see
   `crates/yadorilink-cli/src/device_config.rs` for the default socket
   path, `~/.local/share/yadorilink/daemon.sock`).
7. `./uninstall.sh`, then confirm the unit is gone
   (`systemctl --user status yadorilink-daemon` reports not-found) and
   the binaries are removed (`which yadorilink` / `which
   yadorilink-daemon` both empty).

## What has and hasn't been verified (as of this change)

This packaging was authored and structurally exercised from a **macOS**
development machine, which cannot run `dpkg -i`, `systemctl`, or produce
real Linux (`x86_64-unknown-linux-gnu`) binaries — no Linux Rust target
or cross-linker was available in that environment. What *was* actually
run there, using `dpkg-deb` installed via `brew install dpkg` (which
works identically on any host since it only manipulates `ar`/`tar`
archives, not ELF binaries) and placeholder stand-in files in place of
real Linux binaries:

- `build-deb.sh`'s staging logic end-to-end (directory layout,
  `install` modes, `@VERSION@`/`@ARCH@` substitution into `control`,
  `dpkg-deb --build --root-owner-group`) — produced a structurally valid
  `.deb`.
- `verify-deb.sh` against that output — confirmed `dpkg-deb --info`
  parses the control file correctly and `dpkg-deb --contents` shows the
  expected paths and file modes (binaries `0755`, unit file `0644`).

What was **not** verified, and needs a real Linux machine/VM/CI runner:

- That `cargo build --release --workspace --exclude yadorilink-desktop-app
  --bin yadorilink --bin yadorilink-daemon` actually succeeds on Linux.
- That the resulting real binaries run at all, that `dpkg -i`/`apt
  install` actually installs them, or that `postinst`/`postrm` run
  correctly under real `dpkg`/`apt`.
- That the systemd unit is accepted by a real `systemd --user` instance
  (`systemd-analyze verify` isn't available on macOS either), that
  `Restart=on-failure` actually restarts the daemon after a crash, or
  that `WantedBy=default.target` actually autostarts it at login.
- `lintian` output (not installed in the authoring environment).

## Files

- `build-deb.sh` — builds the workspace binaries and produces the `.deb`
- `verify-deb.sh` — standalone structural verification of a built `.deb`
  (checksum, control metadata, payload contents/modes, optional lintian)
- `debian/control` — control file template (`@VERSION@`/`@ARCH@`
  substituted at build time)
- `debian/postinst`, `debian/postrm` — package scripts (reminders only,
  no automatic systemd enable/disable — see "What the package does" above)
- `debian/copyright` — DEP-5 copyright file, references the bundled
  `LICENSE-MIT`
- `systemd/yadorilink-daemon.service` — the daemon's systemd `--user`
  service unit, installed to `/usr/lib/systemd/user/`
- `uninstall.sh` — companion uninstaller (run as your normal user, not
  with sudo — see its header comment)
