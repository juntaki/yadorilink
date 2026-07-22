# installer/windows: registers/unregisters yadorilink-daemon.exe as a
# per-user Scheduled Task that starts at logon, the same way
# shell-ext/windows/install.ps1 registers the YadoriLinkCfapiHost task for
# yadorilink-cfapi-host.exe (see that script's comments for the full
# rationale) -- a process launched directly by an installer/SSH-invoked
# shell can be torn down along with that shell's session (Windows Job
# Object semantics); -LogonType Interactive runs it in the interactive
# user's session, which yadorilink-daemon needs for the same reason
# yadorilink-cfapi-host does: Explorer-visible placeholder
# creation/hydration happens in that session.
#
# This is deliberately a separate script from shell-ext/windows/install.ps1
# rather than a change to it: install.ps1 is the existing,
# verified-on-a-real-VM source of truth for the shell-extension COM
# registration, ACL-hardened install directory, and Cloud Filter API
# sync-root teardown ordering, none of which yadorilink-daemon.exe is
# involved in. yadorilink-daemon has its own, simpler lifecycle (no COM
# registration, no CfUnregisterSyncRoot ordering requirement) and is
# registered/unregistered by this script, invoked by the installer
# alongside install.ps1 rather than folded into it.
#
# Usage: powershell -ExecutionPolicy Bypass -File daemon-task.ps1 [-Uninstall]
param(
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "daemon-task.ps1 must be run from an elevated PowerShell session."
        exit 1
    }
}

$taskName = "YadoriLinkDaemon"
# Fixed path, matching where shell-ext/windows/install.ps1 installs the
# shell-extension artifacts (Join-Path $env:ProgramFiles "yadorilink") and
# where this installer's [Files] section places yadorilink-daemon.exe.
$installDir = Join-Path $env:ProgramFiles "yadorilink"
$daemonExe = Join-Path $installDir "yadorilink-daemon.exe"

Assert-Administrator

$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($Uninstall) {
    if ($existingTask) {
        Write-Output "Stopping the $taskName scheduled task..."
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }
    Get-Process -Name "yadorilink-daemon" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    if ($existingTask) {
        Write-Output "Removing the $taskName scheduled task..."
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    } else {
        Write-Output "$taskName scheduled task was not registered; nothing to remove."
    }
    exit 0
}

if (-not (Test-Path $daemonExe)) {
    Write-Error "Could not find $daemonExe - yadorilink-daemon.exe must be installed to $installDir first."
    exit 1
}

Write-Output "Registering the $taskName scheduled task..."
$action = New-ScheduledTaskAction -Execute $daemonExe
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null

Write-Output "Starting $taskName now..."
Start-ScheduledTask -TaskName $taskName
