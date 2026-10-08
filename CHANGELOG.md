# Changelog

All notable changes to yadorilink are recorded here. This file accumulates one
entry per **beta** release (the versioned, immutable `beta` channel). The
rolling `nightly` channel is built from `main` on every push and is not tracked
here.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/), and
versions follow [semantic versioning](https://semver.org/) with a `-beta.N`
prerelease suffix (e.g. `v0.1.0-beta.1`).

## [Unreleased]

## [v0.1.0-beta.1] - 2026-10-04

First public beta of YadoriLink: cloud-like file sync without cloud file
storage. Your files stay on your own devices and move directly between your
authorized devices over encrypted connections; the coordination service
(`https://control.yadori.link`) handles accounts, device identity, sharing and
permissions, and never stores file contents.

### What is included

- Folder sync between your devices and with other people, with accounts,
  sharing, roles and revocation.
- Versions, conflict copies and on-demand storage; `yadorilink status`,
  `yadorilink doctor`, and `yadorilink preserved list|restore|retry|discard`
  for items set aside during a reset.
- Platforms: macOS (signed and notarized `.pkg`), Windows 10/11 x64
  (installer, currently unsigned), and Linux x86_64 (`.deb`, binary
  archive, and a `ghcr.io/juntaki/yadorilink-daemon` container image).
- Release builds talk to `https://control.yadori.link` by default; set
  `YADORILINK_COORDINATION_ADDR` to use another coordination service.
- Every download has a SHA-256 checksum; the release also publishes
  `SHA256SUMS-*` files and a signed update manifest.

### Known limitations

- **The Windows installer is unsigned** (`yadorilink-setup-unsigned.exe`).
  SmartScreen warns about an unknown publisher. Verify the SHA-256 published
  next to the file before running it. Signed installers will be published as
  `yadorilink-setup.exe` once a code-signing certificate is available.
- **Windows cannot rebuild a device's history after a very long absence.** If
  a device was offline so long that it needs a history rebuild from a trusted
  checkpoint, the daemon refuses to start it on Windows and reports `the
  rebootstrap is blocked: DurabilityUnsupported`; the folder is left
  untouched. macOS and Linux are not affected.
- **No in-app update download yet.** The updater announces new versions but
  does not download or install them; update by installing the new release (or
  through your package manager).
- **Pre-1.0: upgrades can be incompatible.** There are no compatibility
  migrations between pre-1.0 releases, so update every device to the same
  release together. If a version mismatch prevents startup, remove YadoriLink's
  local application state and credentials and set up again; your synced
  folders and their files are not deleted.

<!--
When cutting a beta release, add a new section ABOVE this comment:

## [vX.Y.Z-beta.N] - YYYY-MM-DD

### Added / Changed / Fixed
- ...

The release job reads the section matching the tag being published and uses it
as the GitHub Release notes body. Never edit or delete a released section —
beta releases are immutable.
-->
