# WinGet manifest

A [WinGet](https://learn.microsoft.com/windows/package-manager/winget/) manifest for
`juntaki.YadoriLink`, in the exact directory layout
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) requires
(`manifests/j/juntaki/YadoriLink/<version>/`) so a submission is a
directory copy into a winget-pkgs fork, not a reformat.

## What's here

- `manifests/j/juntaki/YadoriLink/0.1.0/juntaki.YadoriLink.yaml` — version manifest
- `manifests/j/juntaki/YadoriLink/0.1.0/juntaki.YadoriLink.installer.yaml` — installer manifest
- `manifests/j/juntaki/YadoriLink/0.1.0/juntaki.YadoriLink.locale.en-US.yaml` — default-locale manifest

All three target manifest schema **v1.28.0** (the current schema in
`microsoft/winget-cli`'s `schemas/JSON/manifests/` as of this writing).

## Status

**Not ready to submit.** Two things block a real submission, and neither
can be fixed by editing this manifest:

1. **No release exists yet.** `juntaki/yadorilink` has not cut its first
   tagged release (no `v*` tag, no GitHub Release) — `InstallerUrl` points
   at an asset path that doesn't exist yet, and `InstallerSha256` is a
   placeholder (`000...0`, obviously fake, chosen so a manifest built from
   this file by mistake fails loudly rather than silently).
2. **The Windows Authenticode signing cert isn't configured yet.**
   `oss-public/.github/workflows/release.yml`'s `windows-signed-artifacts`
   job requires `WINDOWS_CODE_SIGN_PFX_BASE64`/`_PASSWORD` as
   `release-signing` Environment secrets (see `installer/RELEASE_SIGNING.md`);
   as of this writing those two secrets are not present in that
   Environment (verified via `gh api repos/juntaki/yadorilink/environments/release-signing/secrets`
   — only the seven `MACOS_*` secrets exist). Submitting an *unsigned*
   installer to `winget-pkgs` is against their policy and a real security
   downgrade for every WinGet user, so this genuinely has to wait.

Once both exist, `.github/workflows/release.yml`'s beta-release job has a
"Record WinGet manifest inputs (no auto-submission)" step that prints the
exact `scripts/ci/update-winget-manifest.sh` invocation (version +
installer sha256) to the workflow run summary, for a maintainer to run by
hand. It deliberately does **not** run that script or commit the result
itself, and does **not** open the winget-pkgs PR either — same
"deliberate, separate, human-gated step" reasoning as "Submission" below:
a release workflow auto-committing generated files back to this repo, or
auto-opening a PR against a third party's repository, is exactly the kind
of unattended action this project's release-signing discipline (required
reviewers, no unattended production credentials) says should stay
human-gated.

## Validation performed

- All three files are valid YAML and validate cleanly against the real
  `manifest.version.1.28.0.json` / `manifest.installer.1.28.0.json` /
  `manifest.defaultLocale.1.28.0.json` JSON schemas fetched from
  `microsoft/winget-cli` (`jsonschema` Draft7Validator, zero errors).
- **Not verified**: the actual `winget validate` CLI command, and
  winget-pkgs' own submission-pipeline checks (URL reachability, a real
  silent-install run in their sandbox). `winget` is Windows-only and this
  environment has no Windows machine or WinGet CLI available. Run
  `winget validate --manifest <this directory>` on a real Windows machine
  before submitting, in addition to the schema check above.

## Key manifest decisions

- **`InstallerType: inno`, `Scope: machine`, `ElevationRequirement:
  elevationRequired`** — `installer/windows/yadorilink.iss` always
  installs to `%ProgramFiles%\yadorilink` with `PrivilegesRequired=admin`;
  these three fields tell WinGet to expect and request that elevation
  rather than assume a per-user install.
- **`ProductCode: '{6F2C6E0A-6E1D-4E62-9E9C-2F7B2C9D6A31}_is1'`** — Inno
  Setup's uninstall registry key is always `<AppId>_is1`, and
  `yadorilink.iss`'s `AppId` is fixed
  (`{6F2C6E0A-6E1D-4E62-9E9C-2F7B2C9D6A31}`) specifically so upgrade
  detection is stable across versions — this is that same GUID, not an
  independently chosen one.
- **`InstallerSwitches.Silent`/`SilentWithProgress` include
  `/PACKAGEMANAGER=winget`** — this is the package-manager-ownership
  marker: `yadorilink.iss`'s `GetPackageManagerParam`/`CurStepChanged`
  reads this flag and writes `InstallSource=winget` to
  `HKLM\Software\yadorilink`, which
  `install_windows::detect_package_manager_marker` reads so the daemon's
  built-in updater defers to `winget upgrade` instead of running its own
  installer over a WinGet-managed install — see `manager::dispatch_install`
  in `crates/yadorilink-daemon/src/update/manager.rs` for the full dispatch
  logic. **This mechanism is unverified against a real WinGet install**
  (no Windows machine in this environment) — matching this repo's
  existing honesty convention for Windows-only code paths (see
  `install_windows.rs`'s own header comment).

## Submission

Opening the actual PR against `microsoft/winget-pkgs` is a deliberate,
separate step nothing in this repository takes automatically, for three
reasons: (1) the two blockers above mean there is nothing real to submit
yet; (2) Microsoft's own manifest/installer validation and human review
process is the actual gate, not something this repo can pre-empt; (3)
submitting a PR to a third party's repository from an unattended
automation is the kind of action this project's release-signing discipline
(required reviewers, no unattended production credentials) says should
stay human-gated. Once both blockers clear, submit by hand:

```sh
gh repo fork microsoft/winget-pkgs --clone
cp -r installer/windows/winget/manifests/j/juntaki/YadoriLink/<version> \
  winget-pkgs/manifests/j/juntaki/YadoriLink/
cd winget-pkgs
git checkout -b juntaki-yadorilink-<version>
git add manifests/j/juntaki/YadoriLink/<version>
git commit -m "New version: juntaki.YadoriLink version <version>"
git push -u origin HEAD
gh pr create --repo microsoft/winget-pkgs --fill
```
