# installer/windows: registers/unregisters yadorilink-status-app.exe (the
# menu-bar/notification-area status app) as a
# per-user Scheduled Task that starts at logon — mirrors daemon-task.ps1's
# own approach for yadorilink-daemon.exe almost exactly (see that script's
# comments for the full rationale on why a Scheduled Task rather than a
# Service, and -LogonType Interactive rather than a batch/system logon:
# the status app needs an interactive desktop session to show a
# notification-area icon, for the identical reason yadorilink-daemon and
# yadorilink-cfapi-host need one). Kept as its own script (not folded into
# daemon-task.ps1) for the same "separate, simpler lifecycle, no shared
# ordering requirement with the shell extension's COM/CfAPI teardown"
# reasoning daemon-task.ps1's own header comment gives for being separate
# from shell-ext/windows/install.ps1.
#
# UNVERIFIED IN THIS ENVIRONMENT: this script was written and syntax
# checked (`Test-ScriptFileInfo`/parser-level) but never run against a
# real Windows machine — the status app was implemented in a
# macOS-only sandbox with no Windows VM available this pass, unlike
# daemon-task.ps1 and shell-ext/windows/install.ps1, which this project's
# history says were verified against a real Windows 11 VM earlier. Treat
# this as a real, honest first draft, not a VM-verified artifact.
#
# Usage: powershell -ExecutionPolicy Bypass -File status-app-task.ps1 [-Uninstall]
param(
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "status-app-task.ps1 must be run from an elevated PowerShell session."
        exit 1
    }
}

$taskName = "YadoriLinkStatusApp"
# Fixed path, matching where this installer's [Files] section places
# yadorilink-status-app.exe (same {app} directory as yadorilink-daemon.exe).
$installDir = Join-Path $env:ProgramFiles "yadorilink"
$statusAppExe = Join-Path $installDir "yadorilink-status-app.exe"

Assert-Administrator

$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($Uninstall) {
    if ($existingTask) {
        Write-Output "Stopping the $taskName scheduled task..."
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }
    Get-Process -Name "yadorilink-status-app" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    if ($existingTask) {
        Write-Output "Removing the $taskName scheduled task..."
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    } else {
        Write-Output "$taskName scheduled task was not registered; nothing to remove."
    }
    exit 0
}

if (-not (Test-Path $statusAppExe)) {
    Write-Error "Could not find $statusAppExe - yadorilink-status-app.exe must be installed to $installDir first."
    exit 1
}

Write-Output "Registering the $taskName scheduled task..."
$action = New-ScheduledTaskAction -Execute $statusAppExe
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
# No -RestartCount/-RestartInterval (unlike daemon-task.ps1's essential-
# service settings): the status app is a user-facing tray icon a user can
# deliberately quit from its own "Quit" menu item — it shouldn't be force-
# relaunched by Task Scheduler within the same session, only at the next
# logon (same discipline the macOS LaunchAgent plist uses: no `KeepAlive`).
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero)
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null

Write-Output "Starting $taskName now..."
Start-ScheduledTask -TaskName $taskName
