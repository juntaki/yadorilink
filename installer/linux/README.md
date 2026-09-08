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
package as a result. `yadorilink-coordination` is a
server-side binary and, as on the other platforms' installers, is
**not** part of this package — deploy it to your own server instead.

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

Then, same as macOS/Windows: `yadorilink login`, `yadorilink device
register ...`, `yadorilink share create <name> --path <folder>`,
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

This packaging was originally authored and structurally exercised from a
**macOS** development machine (see git history), which could not run
`dpkg -i`, `systemctl`, or produce real Linux binaries. A later
verification pass re-ran this package for real on a real Linux (x86_64)
machine, closing most of that original gap:

- `cargo build --release --workspace --exclude yadorilink-desktop-app
  --bin yadorilink --bin yadorilink-daemon` — **succeeds**, real
  `x86_64-unknown-linux-gnu` binaries.
- `./build-deb.sh` end to end, including `dpkg-deb --build
  --root-owner-group` — **produces a real, valid `.deb`** (verified with
  `verify-deb.sh`: checksum, control fields, payload paths and modes all
  correct).
- `lintian` against the built `.deb` — **clean** (run via a disposable
  Ubuntu 24.04 container, since `lintian` wasn't installed on the build
  host either: `docker run ... ubuntu:24.04 ... lintian
  yadorilink_<version>_amd64.deb`).
- A real `dpkg -i`/`apt install` — **succeeds**. Exercised as part of a
  full APT-repository acceptance test (see `installer/linux/apt/`): a
  clean Ubuntu 24.04 container ran the archive-keyring package, `apt-get
  update` (verified the repository's GPG signature), `apt-get install
  yadorilink`, and confirmed `postinst` ran (`Setting up yadorilink
  (0.1.0) ...` plus its reminder text), both binaries execute
  (`yadorilink --version`, `yadorilink-daemon --version`), and `dpkg -s
  yadorilink` reports `Status: install ok installed`.
- `systemd-analyze verify /usr/lib/systemd/user/yadorilink-daemon.service`
  against the **installed** unit (so `ExecStart`'s path actually
  resolves) — **zero errors or warnings**.

What is still **not** verified, and needs a real Linux machine/VM with a
live user session (a plain container has no session bus):

- `systemctl --user enable --now yadorilink-daemon` actually starting the
  daemon, `Restart=on-failure` actually restarting it after a crash, and
  `WantedBy=default.target` actually autostarting it at login.
- `./uninstall.sh`'s live `systemctl --user disable --now` path (its
  `dpkg -r` half is implicitly covered by the apt test above removing the
  package cleanly when the container exits, but the per-user unit
  stop/disable step needs a real session to exercise).

## ARM64 status

`build-deb.sh` was already structurally arm64-aware before this
verification pass (`uname -m`'s `aarch64|arm64` case, `PKG_ARCH`
override) — that part of
the earlier "untested and should be treated as experimental" caveat above
was about the *build itself* having never been run for arm64, not about
missing code. That later verification pass actually ran it:

- `cargo build --release --workspace --exclude yadorilink-desktop-app
  --bin yadorilink --bin yadorilink-daemon` under real arm64 execution
  (QEMU user-mode emulation via `docker run --platform linux/arm64
  rust:1.98-bookworm`, i.e. genuinely running as an arm64 process, not
  just cross-compiled and left unexecuted).
- `PKG_ARCH=arm64 YADORILINK_BIN_DIR=<arm64 binaries> ./build-deb.sh`
  against those binaries, then `dpkg-deb --info`/`--contents` on the
  result (structural check only — this build host cannot execute an
  arm64 ELF outside of QEMU emulation).
- `installer/docker/Dockerfile` had a real bug caught and fixed: the
  builder stage was pinned to `--platform=$BUILDPLATFORM` for build
  speed, which silently produced an **amd64** binary inside the arm64
  runtime image (a wrong-architecture binary gives "no such file or
  directory" at container start, not "exec format error", because the
  copied glibc dynamic linker path doesn't exist in the target image —
  easy to miss without actually running the image). Fixed by dropping
  that pin; see the Dockerfile's own comment. The fix was re-verified
  against real arm64 compilation mechanics (QEMU registered, workspace
  crates compiling for `aarch64`), but the final confirming end-to-end
  `docker run --platform linux/arm64 ... --version` has not been
  completed to a clean pass — see `installer/docker/README.md` for the
  exact status. Treat the arm64 image as unverified until that run
  completes.

Not yet run on real arm64 hardware (only QEMU emulation, which proves the
build/packaging mechanics work but not real-hardware performance or any
QEMU-masked instruction-level issue) — treat this as "arm64 packaging is
now exercised and works" rather than "arm64 has been through the same
depth of manual verification as amd64" (the live systemd-session gaps
above apply here too, and were not re-checked separately for arm64).

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
