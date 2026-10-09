# YadoriLink Windows installer

Builds a self-extracting installer (`yadorilink-setup.exe`) for the four
end-user Windows binaries plus the Explorer shell extension:

- `yadorilink.exe` (CLI)
- `yadorilink-daemon.exe` (sync daemon)
- `yadorilink_shell_ext.dll` (Explorer icon overlays / context menu, COM)
- `yadorilink-cfapi-host.exe` (Cloud Filter API sync-root host)

Built with [Inno Setup 6](https://jrsoftware.org/isinfo.php) rather than
WiX/MSI — Inno's `[Code]`/Pascal-script `Exec()` support made it
straightforward to shell out to real PowerShell scripts at install/
uninstall time and check their exit codes, which is what this installer
needs: it does not reimplement the shell-extension registration logic in
installer XML. Instead it stages an unmodified copy of
`platforms/windows/shell/install.ps1` (the existing, VM-verified COM/ACL/
Cloud-Filter-API registration script) and runs it as-is, plus a new
`daemon-task.ps1` (in this directory) that registers `yadorilink-daemon.exe`
as a logon Scheduled Task the same way `install.ps1` already does for
`yadorilink-cfapi-host.exe`.

## Installing a release (most people)

Download `yadorilink-setup-unsigned.exe` (or `yadorilink-setup.exe` once releases
are signed) and its `.sha256` from
[GitHub Releases](https://github.com/juntaki/yadorilink/releases), run it,
and accept the UAC prompt. Windows 10 or 11, x64, and administrator rights
are required.

**The current release installer is unsigned** (`yadorilink-setup-unsigned.exe`):
SmartScreen will warn, so verify its SHA-256 first. See "Current status" and
"Known limitation" below.

The installer registers a `YadoriLinkDaemon` Scheduled Task so the daemon
starts at every logon. First run, in a terminal:

```powershell
yadorilink login
yadorilink device register --name "my-pc"
yadorilink share create my-share --path C:\Users\me\Documents\some-folder
yadorilink status
```

If something needs attention, `yadorilink status` and `yadorilink doctor`
show what the daemon sees, and `yadorilink preserved list` / `restore` /
`retry` / `discard` manage items set aside when a folder group was reset.

Release builds connect to the YadoriLink coordination service by default;
set `YADORILINK_COORDINATION_ADDR` to use another one. Builds from source
default to `http://127.0.0.1:8787` unless the build was made with
`YADORILINK_DEFAULT_COORDINATION_ADDR` set.

**Updating.** Update every device to the same release: run the newer
`yadorilink-setup.exe`.

**Uninstalling.** Settings → Apps → Installed apps → yadorilink →
Uninstall. This does not touch your synced files, `%APPDATA%\yadorilink`, or
your stored credentials.

**Pre-1.0 reset.** Releases before 1.0 do not promise compatibility
migrations. If a version incompatibility prevents startup, remove
YadoriLink's local application state and credentials and set up again; your
synced folders and their files are not deleted. Run `yadorilink daemon
stop`, then remove the `%APPDATA%\yadorilink` folder and the `yadorilink`
entries in Windows Credential Manager (or run
`yadorilink forget-local-credentials`).

The rest of this file is for building the installer from source.

## Prerequisites

- Windows 10/11 x64.
- [Inno Setup 6](https://jrsoftware.org/isdl.php) (`ISCC.exe`). Install
  silently with:
  ```powershell
  Invoke-WebRequest https://jrsoftware.org/download.php/is.exe -OutFile innosetup.exe
  Start-Process .\innosetup.exe -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-' -Wait
  ```
  This installs to `C:\Program Files (x86)\Inno Setup 6\ISCC.exe` by default.
- The Rust toolchain (same one the rest of this repo uses) and, for the
  shell extension, the MSVC Build Tools (`windows-rs`/COM bindings need
  the MSVC linker) — both already required to build `yadorilink-daemon`/
  `yadorilink-cli`/`platforms/windows/shell` at all.

## Build

From the repository root, on Windows:

```powershell
# 1. Build the workspace binaries (yadorilink.exe, yadorilink-daemon.exe).
cargo build --workspace --release

# 2. Build the shell extension (not a workspace member — see
#  platforms/windows/shell/Cargo.toml's own [workspace] table).
cd platforms\windows\shell
cargo build --release
cd ..\..\..

# 3. Compile the installer. Every build (signed or unsigned) gets a.sha256 sidecar.
powershell -ExecutionPolicy Bypass -File platforms\windows\package\build-installer.ps1
```

Official release installers must use `-Release` with either `-SignToolName`
(signed) or, while no certificate exists, `-Unsigned` (release workflow only;
the result is published under the name `yadorilink-setup-unsigned.exe`). That mode
rebuilds the workspace with
`yadorilink-daemon/enforce-release-trust-root`, so a package cannot silently
reuse an ordinary daemon binary that lacks the release trust-root startup
tripwire.

The resulting installer is written to `platforms\windows\package\Output\yadorilink-setup.exe`,
with `platforms\windows\package\Output\yadorilink-setup.exe.sha256` always written next
to it (release or interim, signed or unsigned — every downloadable release
artifact gets a published checksum).

`yadorilink.iss` locates the four binaries via `BinDir`/`ShellExtDir`
preprocessor constants that default to the standard build layout above
(`target\release` and `platforms\windows\shell\target\release`, both relative
to this directory). Override them if your binaries live elsewhere:

```powershell
$env:YADORILINK_RELEASE_MANIFEST_KEY_ID = "yadorilink-release-2026-01"
$env:YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX = "<64 lowercase hex characters>"
powershell -ExecutionPolicy Bypass -File platforms\windows\package\build-installer.ps1 `
  -BinDir "C:\some\other\target\release" `
  -ShellExtDir "C:\some\other\shell-ext\target\release"
```

These variables contain only the identifier and public half of the offline
update signing key; never copy the private key to
the Windows build host.

Release builds must be Authenticode-signed through an Inno Setup SignTool
profile:

```powershell
powershell -ExecutionPolicy Bypass -File platforms\windows\package\build-installer.ps1 `
  -Release `
  -SignToolName yadorilink-release
```

## What the installer does

1. Copies the four binaries into `%ProgramFiles%\yadorilink`.
2. Runs `platforms/windows/shell/install.ps1` (staged, unmodified) elevated,
   which: ACL-hardens `%ProgramFiles%\yadorilink` so only Administrators/
   SYSTEM can write to it (Explorer/limited-user processes get
   read+execute only), registers `yadorilink_shell_ext.dll` via
   `regsvr32`, restarts Explorer, and registers+starts a
   `YadoriLinkCfapiHost` Scheduled Task (`-LogonType Interactive`) running
   `yadorilink-cfapi-host.exe`.
3. Runs `daemon-task.ps1` elevated, which registers+starts a
   `YadoriLinkDaemon` Scheduled Task (`-LogonType Interactive`, same
   pattern) running `yadorilink-daemon.exe`, so the sync daemon starts
   automatically at every logon instead of requiring a manual
   `yadorilink daemon start` from a terminal every session.

Uninstalling (via "Apps & Features" or the generated uninstaller) runs
`daemon-task.ps1 -Uninstall` (stops the process, removes the
`YadoriLinkDaemon` task) and then `install.ps1 -Uninstall` (stops/removes
the `YadoriLinkCfapiHost` task, unregisters every Cloud Filter API sync
root the host ever registered, unregisters the COM DLL, then deletes
`%ProgramFiles%\yadorilink`) — in that order, since `install.ps1 -Uninstall`
deletes the whole install directory (including `daemon-task.ps1`) as its
last step.

## Signing and checksums

Release installers are Authenticode-signed once a code-signing certificate is
configured. Until then the release installer is built with `-Release
-Unsigned` and published as `yadorilink-setup-unsigned.exe`, always with its
`.sha256` sidecar. Windows SmartScreen shows an "unknown publisher" warning
for unsigned builds.

### Current status: the installer is unsigned

No Windows code-signing certificate exists yet, so the release installer is
**not Authenticode-signed**. It is published as `yadorilink-setup-unsigned.exe`
(with `yadorilink-setup-unsigned.exe.sha256`) so it cannot be mistaken for a
signed one. Consequences:

- Windows SmartScreen shows "Windows protected your PC" / "unknown publisher".
  Choose **More info -> Run anyway** only after the checksum below matches.
- Verify the download against the SHA-256 published next to it on the release
  page (also listed in `SHA256SUMS-windows`):

  ```powershell
  $expected = (Get-Content .\yadorilink-setup-unsigned.exe.sha256).Split()[0]
  $actual = (Get-FileHash -Algorithm SHA256 .\yadorilink-setup-unsigned.exe).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw "checksum mismatch" }
  ```

Releases built after a certificate is configured are signed and published as
`yadorilink-setup.exe`.

### Known limitation: history rebuild is not supported on Windows

If a device stays offline so long that it can no longer catch up from its
peers and needs a rebuild of its synced history from a trusted checkpoint,
that rebuild is **not supported on Windows yet**. The daemon refuses to start
it, before touching any file in the folder, and reports `the rebootstrap is
blocked: DurabilityUnsupported`. The folder is left as it was. Windows has no
verified way to make a directory change durable, which the rebuild's safety
barrier requires. Devices that stay reasonably in sync are not affected; on
macOS and Linux the rebuild works.

## Testing

There is no automated test for this installer (and it is intentionally
not wired into CI). Verify manually on a real Windows VM/machine:
install, confirm the four binaries + two Scheduled Tasks (`YadoriLinkDaemon`,
`YadoriLinkCfapiHost`) exist and the tasks are running, confirm Explorer's
context menu shows the yadorilink submenu on a test file, then uninstall
and confirm the binaries, Scheduled Tasks, and COM registration are all
gone.

## WinGet

`winget/manifests/j/juntaki/YadoriLink/` holds a WinGet manifest for this
installer — see `winget/README.md` for its build/validation/submission
status. One detail that affects this directory: `yadorilink.iss`'s
`[Code]` section accepts an undocumented `/PACKAGEMANAGER=<name>` command-
line switch, which writes `InstallSource=<name>` to
`HKLM\Software\yadorilink` (cleaned up on uninstall). The WinGet manifest's
`InstallerSwitches` pass `/PACKAGEMANAGER=winget`; the running daemon's
`install_windows::detect_package_manager_marker` reads that registry value
so its built-in updater defers to `winget upgrade` instead of running its
own installer over a WinGet-managed install (see `manager::dispatch_install`
in `crates/yadorilink-daemon/src/update/manager.rs`). **This has not been
verified against a real WinGet install** — no Windows machine was
available for this verification pass; see `winget/README.md`.
