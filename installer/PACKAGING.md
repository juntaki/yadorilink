# Package-manager distribution

Overview of every install path yadorilink ships or is preparing to ship,
and the one rule that ties them together: **whichever path a user chose
owns their own updates from then on** — a Homebrew/apt/WinGet/Store
install is detected at runtime
(`crates/yadorilink-daemon/src/update/install_{macos,windows,linux}.rs`)
and the built-in updater (`yadorilink update install`) defers to that
package manager instead of racing it. This page is the map of where each
path's packaging actually lives.

| Path | Platform | What it ships | Where | Status |
|---|---|---|---|---|
| `.pkg` (direct download) | macOS | CLI + daemon + status app + Finder integration, signed & notarized | `installer/macos/` | Shipping (build-health always; signed on trusted events) |
| Homebrew Cask | macOS | The same signed `.pkg`, via `brew install --cask` | `juntaki/homebrew-yadorilink` (separate repo) `Casks/yadorilink.rb` | Tap live; placeholder version/sha256 until the first real release |
| Homebrew Formula | macOS + Linux | CLI + daemon only, built from source | `juntaki/homebrew-yadorilink` `Formula/yadorilink.rb` | Tap live; same placeholder caveat |
| `.deb` (direct download / `dpkg -i`) | Linux (Debian/Ubuntu) | CLI + daemon + systemd `--user` unit | `installer/linux/` | Shipping (amd64 verified on real Linux + real apt; arm64 packaging exercised via QEMU, not yet on real hardware) |
| APT repository | Linux (Debian/Ubuntu) | The same `.deb`, via `apt install` | `installer/linux/apt/`, `scripts/ci/build-apt-repo.sh`, served by `coordination-worker`'s `/apt` route | Tooling built and verified end-to-end against a dev key; production signing key not yet generated (see `installer/linux/apt/README.md`) |
| `.exe` (Inno Setup, direct download) | Windows | CLI + daemon + status app + shell integration, Authenticode-signed | `installer/windows/` | Build-health always; **signing not yet configured** (`WINDOWS_CODE_SIGN_PFX_*` secrets absent as of this writing) |
| WinGet manifest | Windows | The same signed `.exe`, via `winget install` | `installer/windows/winget/` | Manifest built and schema-validated; **not submittable yet** — no release exists, and Windows signing isn't configured either (see `installer/windows/winget/README.md`) |
| Docker image | linux/amd64, linux/arm64 | `yadorilink-daemon` only, headless | `installer/docker/`, published to `ghcr.io/juntaki/yadorilink-daemon` | amd64 built and run-verified; **arm64 build fixed a real wrong-architecture bug but the fix is not yet re-confirmed end to end** (disk-constrained build host — see `installer/docker/README.md`'s "Verification performed") |

## Install-source detection

Every non-`standalone` path above is detectable at runtime by the daemon
itself (`crates/yadorilink-daemon/src/update/install_{macos,windows,linux}.rs`),
so the built-in updater (`yadorilink update install`) always defers to the
package manager that actually owns the install instead of racing it:

| `install_source` | How it's detected |
|---|---|
| `microsoft_store` | `WindowsApps` in the running executable's path (structural) |
| `winget` | A registry marker (`HKLM\Software\yadorilink\InstallSource`) the Inno Setup installer writes when invoked with WinGet's `/PACKAGEMANAGER=winget` switch |
| `homebrew` | A marker file (`/etc/yadorilink/install_source`) the Cask's `postflight` writes |
| `apt` | `dpkg-query -S` reporting the *exact running binary* (canonicalized path) as owned by the `yadorilink` package (no marker needed — dpkg already tracks this) |
| `standalone` | Absence of every marker/detection above |

See `manager::dispatch_install` in
`crates/yadorilink-daemon/src/update/manager.rs` for the full table of
dispatch outcomes per `install_source`.

## Release automation

`oss-public/.github/workflows/release.yml`'s `beta-release` job (an
immutable `v*` tag) is the one place all of this wires together for a
real release:

1. Builds and signs the macOS `.pkg` / Windows `.exe` / Linux `.deb` (existing).
2. Builds and signs the APT repository, publishes it to R2 (`Build and
   publish the APT repository` step) — gated on `APT_SIGNING_KEY`
   existing in the `release-signing` Environment.
3. Dispatches `juntaki/homebrew-yadorilink`'s `bump-tap.yml` with the new
   version and checksums (`Notify the Homebrew tap of a new release`
   step) — gated on `HOMEBREW_TAP_DISPATCH_TOKEN`.
4. Records the WinGet manifest's two real inputs (version, installer
   sha256) in the job summary — does **not** commit them or run
   `scripts/ci/update-winget-manifest.sh` itself; see
   `installer/windows/winget/README.md`'s "Status" section for why that
   stays a manual, human-gated step, same as WinGet submission itself.

`docker-artifacts` (multi-arch image, GHCR) runs independently on both
`main` (a rolling `nightly` tag) and `v*` tags (an immutable version tag +
floating `latest`).

## What still needs a human decision

- **APT signing key**: not generated as part of this change — see
  `installer/linux/apt/README.md`'s "Signing key custody".
- **`HOMEBREW_TAP_DISPATCH_TOKEN`**: a fine-grained PAT scoped only to
  `juntaki/homebrew-yadorilink` (`contents: write`), stored as a
  `release-signing` Environment secret on `juntaki/yadorilink` — not yet
  created.
- **WinGet PR submission**: intentionally not automated at all — see
  `installer/windows/winget/README.md`'s "Submission".
- **`release-signing` Environment protection**: verified via `gh api` that
  this Environment currently has **no required-reviewers rule**, despite
  `docs/UPDATE_SIGNING.md` mandating one. This is a pre-existing gap, not
  something introduced here, and choosing reviewers is a maintainer/org
  decision this repository's tooling shouldn't make unilaterally — fixing
  it just needs a maintainer to add a required-reviewers rule to that
  Environment in repository Settings.
