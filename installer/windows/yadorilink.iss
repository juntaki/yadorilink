; installer/windows/yadorilink.iss
;
; Inno Setup script for yadorilink's Windows installer. Packages the five
; end-user Windows binaries (yadorilink.exe, yadorilink-daemon.exe,
; yadorilink_shell_ext.dll, yadorilink-cfapi-host.exe,
; yadorilink-status-app.exe) into %ProgramFiles%\yadorilink and, at
; install/uninstall time, invokes:
;  - shell-ext/windows/install.ps1 UNMODIFIED (staged into
;  {app}\_stage — see the [Files] section below) to do the COM
;  registration / ACL-hardened install directory / Cloud Filter API
;  sync-root registration, exactly as already verified on a real
;  Windows 11 VM. Do not fork or reimplement that script's logic here.
;  - daemon-task.ps1 (this directory) to register yadorilink-daemon.exe as
;  a logon Scheduled Task, the one piece install.ps1 intentionally
;  doesn't cover (it only ever managed the shell extension + cfapi
;  host).
;  - status-app-task.ps1 (this directory) to
;  register yadorilink-status-app.exe (the menu-bar/notification-area
;  status app) as its own logon Scheduled Task. UNVERIFIED ON A REAL
;  WINDOWS MACHINE — see that script's own header comment.
;
; Build with Inno Setup 6 (ISCC.exe) — see README.md in this directory.

#define MyAppName "YadoriLink"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "juntaki"
#define MyAppURL "https://github.com/juntaki/yadorilink"

; Overridable via `iscc /DBinDir=... /DShellExtDir=... yadorilink.iss`.
; Defaults assume the standard build layout relative to this.iss file:
;  Cargo build --workspace --release ->..\..\target\release
;  Cargo build --release (in shell-ext\windows) ->..\..\shell-ext\windows\target\release
#ifndef BinDir
  #define BinDir "..\..\target\release"
#endif
#ifndef ShellExtDir
  #define ShellExtDir "..\..\shell-ext\windows\target\release"
#endif
#define InstallPs1Source "..\..\shell-ext\windows\install.ps1"

; Optional release signing. Pass e.g.
;  iscc /DYadoriLinkSignTool=my-sign-tool installer\windows\yadorilink.iss
; where `my-sign-tool` is an Inno Setup SignTool profile. The companion
; build-installer.ps1 wrapper enforces this for release builds and writes a
; SHA-256 sidecar for interim unsigned builds.
#ifdef YadoriLinkSignTool
  #define HasYadoriLinkSignTool
#endif

[Setup]
; Fixed AppId so re-running the installer / Add-Remove-Programs upgrade
; detection is stable across versions.
AppId={{6F2C6E0A-6E1D-4E62-9E9C-2F7B2C9D6A31}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
; %ProgramFiles%\yadorilink on a 64-bit install — must match the fixed
; `Join-Path $env:ProgramFiles "yadorilink"` path both install.ps1 and
; daemon-task.ps1 hardcode.
DefaultDirName={autopf}\yadorilink
DisableProgramGroupPage=yes
; Everything this installer does (regsvr32, ACL hardening, Scheduled
; Tasks bound to HKLM) requires an elevated session, same as install.ps1
; itself already asserts.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=yadorilink-setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\yadorilink.exe
#ifdef HasYadoriLinkSignTool
SignTool={#YadoriLinkSignTool}
SignedUninstaller=yes
#else
; Local/interim builds may remain unsigned, but release builds must pass a
; SignTool profile via build-installer.ps1. Unsigned artifacts get a
; yadorilink-setup.exe.sha256 sidecar from that wrapper.
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; on a fresh install only, offer to open
; the GUI onboarding wizard on the finish page. `runasoriginaluser` drops
; the installer's elevation so the wizard runs as the human, `nowait` so Setup
; doesn't block on it, `skipifsilent` so unattended installs never pop a
; window, and the `IsFreshInstall` check suppresses it on upgrades (a device
; already registered ⇒ `%APPDATA%\yadorilink\device.json` exists).
[Run]
Filename: "{app}\yadorilink-status-app.exe"; Parameters: "--window onboarding"; \
  Description: "Set up YadoriLink now"; \
  Flags: postinstall nowait skipifsilent runasoriginaluser; Check: IsFreshInstall

[Files]
; The five end-user binaries, installed flat into {app}.
Source: "{#BinDir}\yadorilink.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\yadorilink-daemon.exe"; DestDir: "{app}"; Flags: ignoreversion
; Built by the same `cargo build --workspace --release` as
; yadorilink.exe/yadorilink-daemon.exe above (it's a regular workspace
; member, crates/yadorilink-desktop-app), so it lands in the same {#BinDir}.
Source: "{#BinDir}\yadorilink-status-app.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ShellExtDir}\yadorilink_shell_ext.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ShellExtDir}\yadorilink-cfapi-host.exe"; DestDir: "{app}"; Flags: ignoreversion

; daemon-task.ps1/status-app-task.ps1 live directly under {app} since they
; only ever operate on the fixed %ProgramFiles%\yadorilink path (they don't
; need a dev-style target\release layout the way install.ps1 does).
Source: "daemon-task.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "status-app-task.ps1"; DestDir: "{app}"; Flags: ignoreversion

; --- Staging area for the unmodified install.ps1 ---------------------
; install.ps1 resolves its build artifacts via
; `Join-Path $PSScriptRoot "target\release\<name>"` — i.e. it expects to
; be run from a directory shaped like a `shell-ext/windows/` dev
; checkout with a sibling `target\release\` containing the two shell-ext
; binaries. Rather than editing install.ps1 to accept a different
; layout, this installer recreates that expected layout under
; {app}\_stage so the real, unmodified script just works.
Source: "{#InstallPs1Source}"; DestDir: "{app}\_stage"; Flags: ignoreversion
Source: "{#ShellExtDir}\yadorilink_shell_ext.dll"; DestDir: "{app}\_stage\target\release"; Flags: ignoreversion
Source: "{#ShellExtDir}\yadorilink-cfapi-host.exe"; DestDir: "{app}\_stage\target\release"; Flags: ignoreversion

[Code]
function ExecPowerShellScript(const ScriptPath: String; const ExtraArgs: String; const LogLabel: String): Boolean;
var
  ResultCode: Integer;
  Params: String;
  PowerShellPath: String;
  Ran: Boolean;
begin
  Params := '-NoProfile -ExecutionPolicy Bypass -File "' + ScriptPath + '"';
  if ExtraArgs <> '' then
    Params := Params + ' ' + ExtraArgs;

  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Log('Running ' + LogLabel + ': ' + PowerShellPath + ' ' + Params);
  Ran := Exec(PowerShellPath, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  if (not Ran) then
  begin
    Log(LogLabel + ' failed to launch.');
    Result := False;
  end
  else if ResultCode <> 0 then
  begin
    Log(LogLabel + ' exited with code ' + IntToStr(ResultCode) + '.');
    Result := False;
  end
  else
  begin
    Log(LogLabel + ' completed successfully.');
    Result := True;
  end;
end;

// true when this machine has never
// registered a YadoriLink device — i.e. `%APPDATA%\yadorilink\device.json`
// does not exist — so the finish-page "Set up YadoriLink now" launch only
// appears on a genuinely fresh install, not an upgrade. `{userappdata}`
// resolves to the profile of the user running Setup.
function IsFreshInstall: Boolean;
begin
  Result := not FileExists(ExpandConstant('{userappdata}\yadorilink\device.json'));
end;

// Package-manager ownership (see docs/AUTOMATIC_UPDATES.md's
// "Package-manager-owned installs never self-update"): a WinGet manifest
// invokes this exact installer -- the same one a manual download would
// run, into the same %ProgramFiles%\yadorilink layout -- so there is no
// structural signal (unlike the Microsoft Store's WindowsApps path) this
// installer's own layout can offer. The WinGet manifest's
// InstallerSwitches.Silent therefore appends `/PACKAGEMANAGER=winget` to
// the normal silent-install flags; this scans for that switch (Inno Setup
// has no built-in support for arbitrary custom /switches, only ParamStr)
// and, if present, records it so the running daemon's
// `install_windows::detect_package_manager_marker` can defer self-update
// to `winget upgrade` instead of running its own installer over an
// install WinGet believes it owns.
function GetPackageManagerParam: String;
var
  i: Integer;
  p: String;
  prefix: String;
begin
  Result := '';
  prefix := '/PACKAGEMANAGER=';
  for i := 1 to ParamCount do
  begin
    p := ParamStr(i);
    if Copy(p, 1, Length(prefix)) = prefix then
    begin
      Result := Copy(p, Length(prefix) + 1, MaxInt);
      Exit;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ShellExtOk, DaemonTaskOk, StatusAppTaskOk: Boolean;
  PackageManager: String;
begin
  if CurStep = ssPostInstall then
  begin
    PackageManager := GetPackageManagerParam;
    if PackageManager <> '' then
    begin
      // HKLM (not HKCU): this installer always runs elevated
      // (PrivilegesRequired=admin above), and the daemon must be able to
      // read this value regardless of which user account it later runs
      // as. {#MyAppName}'s AppId-scoped uninstall key already lives under
      // HKLM for the same reason; this is a small, separate key
      // (`Software\yadorilink`) rather than reusing that uninstall entry
      // so `install_windows::detect_package_manager_marker` doesn't need
      // to know Inno Setup's uninstall-key layout.
      RegWriteStringValue(HKLM, 'Software\yadorilink', 'InstallSource', PackageManager);
    end;

    if not WizardSilent() then
    begin
      WizardForm.StatusLabel.Caption := 'Registering the yadorilink shell extension...';
      WizardForm.Refresh;
    end;
    ShellExtOk := ExecPowerShellScript(ExpandConstant('{app}\_stage\install.ps1'), '', 'shell-ext install.ps1');
    // WizardSilent guards the MsgBox calls below: a blocking MsgBox
    // during a /SILENT or /VERYSILENT run (which /SUPPRESSMSGBOXES does
    // NOT suppress — that flag only affects Inno's own built-in message
    // boxes, not ones this [Code] section creates) would hang the
    // installer process forever with no one able to dismiss it. Failures
    // are still recorded via Log either way (Setup's own log, or
    // /LOG=... on the command line) for unattended runs.
    if (not ShellExtOk) and (not WizardSilent()) then
      MsgBox('Setup could not register the yadorilink shell extension (Explorer icon overlays / ' +
             'context menu / Cloud Filter API sync-root host). yadorilink.exe and yadorilink-daemon.exe ' +
             'were still installed and can be used from a terminal. See %TEMP%\Setup Log*.txt for ' +
             'details, or re-run "' + ExpandConstant('{app}') + '\_stage\install.ps1" elevated by hand.',
             mbError, MB_OK);

    if not WizardSilent() then
    begin
      WizardForm.StatusLabel.Caption := 'Registering the yadorilink-daemon startup task...';
      WizardForm.Refresh;
    end;
    DaemonTaskOk := ExecPowerShellScript(ExpandConstant('{app}\daemon-task.ps1'), '', 'daemon-task.ps1');
    if (not DaemonTaskOk) and (not WizardSilent()) then
      MsgBox('Setup could not register yadorilink-daemon to start automatically at logon. You can start ' +
             'it manually with "yadorilink daemon start" or by running yadorilink-daemon.exe directly.',
             mbError, MB_OK);

    // register the status app's own logon
    // Scheduled Task the same way, as a separate (non-fatal-to-the-rest-
    // of-setup) step — a user who declines/can't get the tray icon
    // running can still use the CLI and daemon fully, matching the
    // shell-extension failure above's "still installed and usable from a
    // terminal" precedent.
    if not WizardSilent() then
    begin
      WizardForm.StatusLabel.Caption := 'Registering the yadorilink status app startup task...';
      WizardForm.Refresh;
    end;
    StatusAppTaskOk := ExecPowerShellScript(ExpandConstant('{app}\status-app-task.ps1'), '', 'status-app-task.ps1');
    if (not StatusAppTaskOk) and (not WizardSilent()) then
      MsgBox('Setup could not register the yadorilink status app to start automatically at logon. You can ' +
             'start it manually by running yadorilink-status-app.exe directly.',
             mbError, MB_OK);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    // Order matters. Tear down the yadorilink-daemon and status-app
    // Scheduled Tasks first (neither has an ordering dependency on
    // anything else), THEN hand off to the unmodified install.ps1
    // -Uninstall, which — per its own hard-won comment — must
    // stop/unregister the cfapi host BEFORE calling CfUnregisterSyncRoot,
    // and which recursively deletes %ProgramFiles%\yadorilink (this
    // installer's {app}) as its last step, taking _stage\,
    // daemon-task.ps1, status-app-task.ps1, and the rest of {app} with it.
    ExecPowerShellScript(ExpandConstant('{app}\daemon-task.ps1'), '-Uninstall', 'daemon-task.ps1 -Uninstall');
    ExecPowerShellScript(ExpandConstant('{app}\status-app-task.ps1'), '-Uninstall', 'status-app-task.ps1 -Uninstall');
    ExecPowerShellScript(ExpandConstant('{app}\_stage\install.ps1'), '-Uninstall', 'shell-ext install.ps1 -Uninstall');
    // Clean up the package-manager marker `CurStepChanged` above may have
    // written; RegDeleteKeyIncludingSubkeys is a no-op (returns True) if
    // it was never created (a manual/standalone install).
    RegDeleteKeyIncludingSubkeys(HKLM, 'Software\yadorilink');
  end;
end;
