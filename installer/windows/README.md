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
`shell-ext/windows/install.ps1` (the existing, VM-verified COM/ACL/
Cloud-Filter-API registration script) and runs it as-is, plus a new
`daemon-task.ps1` (in this directory) that registers `yadorilink-daemon.exe`
as a logon Scheduled Task the same way `install.ps1` already does for
`yadorilink-cfapi-host.exe`.

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
  `yadorilink-cli`/`shell-ext/windows` at all.

## Build

From the repository root, on Windows:

```powershell
# 1. Build the workspace binaries (yadorilink.exe, yadorilink-daemon.exe).
cargo build --workspace --release

# 2. Build the shell extension (not a workspace member — see
#  shell-ext/windows/Cargo.toml's own [workspace] table).
cd shell-ext\windows
cargo build --release
cd ..\..

# 3. Compile the installer. Every build (signed or unsigned) gets a.sha256 sidecar.
powershell -ExecutionPolicy Bypass -File installer\windows\build-installer.ps1
```

Official release installers must use `-Release` and `-SignToolName`. That mode
rebuilds the workspace with
`yadorilink-daemon/enforce-release-trust-root`, so a package cannot silently
reuse an ordinary daemon binary that lacks the release trust-root startup
tripwire.

The resulting installer is written to `installer\windows\Output\yadorilink-setup.exe`,
with `installer\windows\Output\yadorilink-setup.exe.sha256` always written next
to it (release or interim, signed or unsigned — every downloadable release
artifact gets a published checksum).

`yadorilink.iss` locates the four binaries via `BinDir`/`ShellExtDir`
preprocessor constants that default to the standard build layout above
(`target\release` and `shell-ext\windows\target\release`, both relative
to this directory). Override them if your binaries live elsewhere:

```powershell
$env:YADORILINK_RELEASE_MANIFEST_KEY_ID = "yadorilink-release-2026-01"
$env:YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX = "<64 lowercase hex characters>"
powershell -ExecutionPolicy Bypass -File installer\windows\build-installer.ps1 `
  -BinDir "C:\some\other\target\release" `
  -ShellExtDir "C:\some\other\shell-ext\target\release"
```

These variables contain only the identifier and public half of the offline
update signing key. See `docs/UPDATE_SIGNING.md`; never copy the private key to
the Windows build host.

Release builds must be Authenticode-signed through an Inno Setup SignTool
profile:

```powershell
powershell -ExecutionPolicy Bypass -File installer\windows\build-installer.ps1 `
  -Release `
  -SignToolName yadorilink-release
```

## What the installer does

1. Copies the four binaries into `%ProgramFiles%\yadorilink`.
2. Runs `shell-ext/windows/install.ps1` (staged, unmodified) elevated,
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

Release installers must be Authenticode-signed. Interim unsigned builds are
allowed only for local/manual testing and must be distributed with the
generated `.sha256` sidecar. Windows SmartScreen will show an "unknown
publisher" warning for unsigned builds.

## Testing

There is no automated test for this installer (and it is intentionally
not wired into CI). Verify manually on a real Windows VM/machine:
install, confirm the four binaries + two Scheduled Tasks (`YadoriLinkDaemon`,
`YadoriLinkCfapiHost`) exist and the tasks are running, confirm Explorer's
context menu shows the yadorilink submenu on a test file, then uninstall
and confirm the binaries, Scheduled Tasks, and COM registration are all
gone.
