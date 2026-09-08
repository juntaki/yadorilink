# Changelog

All notable changes to yadorilink are recorded here. This file accumulates one
entry per **beta** release (the versioned, immutable `beta` channel). The
rolling `nightly` channel is built from `main` on every push and is not tracked
here.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/), and
versions follow [semantic versioning](https://semver.org/) with a `-beta.N`
prerelease suffix (e.g. `v0.1.0-beta.1`).

## [Unreleased]

- Signed, notarized macOS `.pkg` and Authenticode-signed Windows installer are
  now produced by CI.
- Per-channel signed update manifests are published for the `nightly` and
  `beta` channels and served from the coordination edge at
  `https://yadorilink.juntaki.com/updates/<channel>/manifest.json`.
- Package-manager distribution: a Homebrew tap
  (`juntaki/homebrew-yadorilink`, Cask + Formula), an APT repository
  (`https://yadorilink.juntaki.com/apt`, `curl -fsSL
  https://yadorilink.juntaki.com/apt/install.sh | sudo sh`), a Docker
  image (`ghcr.io/juntaki/yadorilink-daemon`, `linux/amd64`+`linux/arm64`),
  and a WinGet manifest (not yet submitted). The built-in updater now
  detects an apt/Homebrew/WinGet-managed install and defers to that
  package manager instead of self-updating. See `installer/PACKAGING.md`
  for the full map, including which pieces are not yet live (no release
  has been tagged yet, so the Cask/Formula/WinGet manifest still point at
  placeholder checksums).

<!--
When cutting a beta release, add a new section ABOVE this comment:

## [vX.Y.Z-beta.N] - YYYY-MM-DD

### Added / Changed / Fixed
- ...

The release job reads the section matching the tag being published and uses it
as the GitHub Release notes body. Never edit or delete a released section —
beta releases are immutable.
-->
