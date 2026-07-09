# build-filebox-mvp task 9.5 / on-demand-sync task 6.6: registers the
# yadorilink shell icon overlay identifiers (COM, regsvr32) and the
# yadorilink-cfapi-host process (Cloud Filter API sync-root
# registration/placeholders/fetch-data callbacks, tasks 6.1-6.3) as a
# Scheduled Task, so it survives logoff/session teardown the way a
# directly-launched child process wouldn't. Must run elevated (regsvr32
# writes to HKEY_LOCAL_MACHINE; Register-ScheduledTask needs admin for a
# machine-wide task).
# Usage: powershell -ExecutionPolicy Bypass -File install.ps1 [-Uninstall]
param(
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "install.ps1 must be run from an elevated PowerShell session."
        exit 1
    }
}

function Resolve-BuildArtifact {
    param(
        [string]$FileName,
        [switch]$Required
    )

    $release = Join-Path $PSScriptRoot "target\release\$FileName"
    if (Test-Path $release) {
        return $release
    }
    $debug = Join-Path $PSScriptRoot "target\debug\$FileName"
    if (Test-Path $debug) {
        return $debug
    }
    if ($Required) {
        Write-Error "Could not find $FileName - build the crate first (cargo build [--release])."
        exit 1
    }
    return $null
}

function New-InstallDirectoryAcl {
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagate = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18"),
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        $propagate,
        $allow
    ))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544"),
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        $propagate,
        $allow
    ))
    # Explorer and the limited scheduled-task process still need to load
    # the DLL/EXE; the security boundary is that only administrators and
    # SYSTEM can write or replace anything under this directory.
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-545"),
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inherit,
        $propagate,
        $allow
    ))
    return $acl
}

function Get-WriteLikeRights {
    $rights = [System.Security.AccessControl.FileSystemRights]0
    # Deliberately does NOT OR in FullControl or Modify: both are composite
    # rights that, per .NET's own FileSystemRights bit layout, already
    # include the read/execute family of bits (ReadData, ReadAttributes,
    # ReadExtendedAttributes, ReadPermissions, ExecuteFile, Synchronize) —
    # the same bits ReadAndExecute is made of. OR-ing either of them in here
    # would make this mask overlap with a *pure* ReadAndExecute grant (the
    # Users rule New-InstallDirectoryAcl intentionally adds below), which
    # would make Assert-AdminOnlyWritableAcl reject that rule as "write-like"
    # unconditionally, on every machine, regardless of what it actually
    # grants. FullControl/Modify grants are still caught: they're supersets
    # of the atomic write bits enumerated here, so the `-band` below is still
    # nonzero for them.
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::AppendData
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::CreateFiles
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::Delete
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::Write
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::WriteData
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
    return $rights
}

function Assert-AdminOnlyWritableAcl {
    param(
        [string]$Path,
        [switch]$RequireProtected
    )

    $acl = Get-Acl -LiteralPath $Path
    if ($RequireProtected -and -not $acl.AreAccessRulesProtected) {
        Write-Error "$Path inherits ACLs; refusing to register a shell extension from an inherited-write location."
        exit 1
    }

    $allowedWriterSids = @("S-1-5-18", "S-1-5-32-544")
    $writeLikeRights = Get-WriteLikeRights
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        if (($rule.FileSystemRights -band $writeLikeRights) -eq 0) {
            continue
        }

        $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($allowedWriterSids -notcontains $sid) {
            Write-Error "$Path grants write-like access to $($rule.IdentityReference); refusing to register."
            exit 1
        }
    }
}

function Install-ProgramFilesArtifacts {
    param(
        [string]$SourceDll,
        [string]$SourceCfapiHost
    )

    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    $acl = New-InstallDirectoryAcl
    Set-Acl -LiteralPath $installDir -AclObject $acl
    Assert-AdminOnlyWritableAcl -Path $installDir -RequireProtected

    Remove-Item -LiteralPath $installedDll, $installedCfapiHost -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $SourceDll -Destination $installedDll -Force
    Copy-Item -LiteralPath $SourceCfapiHost -Destination $installedCfapiHost -Force
    Assert-AdminOnlyWritableAcl -Path $installedDll
    Assert-AdminOnlyWritableAcl -Path $installedCfapiHost
}

$taskName = "YadoriLinkCfapiHost"
$systemRoot = $env:WINDIR
if ([string]::IsNullOrWhiteSpace($systemRoot)) {
    $systemRoot = "$env:SystemDrive\Windows"
}
$system32 = Join-Path $systemRoot "System32"
$regsvr32Exe = Join-Path $system32 "regsvr32.exe"
$explorerExe = Join-Path $systemRoot "explorer.exe"
$installDir = Join-Path $env:ProgramFiles "yadorilink"
$installedDll = Join-Path $installDir "yadorilink_shell_ext.dll"
$installedCfapiHost = Join-Path $installDir "yadorilink-cfapi-host.exe"

Assert-Administrator

if ($Uninstall) {
    # Stop the running yadorilink-cfapi-host process (and its Scheduled
    # Task) BEFORE unregistering sync roots. Verified against real cfapi
    # on a Windows 11 VM: CfUnregisterSyncRoot fails with
    # ERROR_CLOUD_FILE_INVALID_REQUEST (0x8007017C) while a provider
    # process is still connected (CfConnectSyncRoot) to that root — a
    # connection is tied to process lifetime, so stopping the process
    # that made it is what actually tears the connection down; doing
    # --unregister-all first (the original, wrong order here) leaves the
    # long-lived host's connection still live and every unregistration
    # fails.
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Output "Stopping the $taskName scheduled task..."
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }
    Get-Process -Name "yadorilink-cfapi-host" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $cfapiHost = if (Test-Path $installedCfapiHost) {
        $installedCfapiHost
    } else {
        Resolve-BuildArtifact -FileName "yadorilink-cfapi-host.exe"
    }

    # Unregister every Cloud Filter API sync root this host has ever
    # registered (task 6.6) — this call reads its own on-disk record of
    # registered roots (%LOCALAPPDATA%\yadorilink\cfapi_sync_roots.txt) and
    # does not require yadorilink-daemon to be running.
    if ($cfapiHost) {
        Write-Output "Unregistering Cloud Filter API sync roots..."
        & "$cfapiHost" --unregister-all
    } else {
        Write-Warning "Could not find yadorilink-cfapi-host.exe; skipping Cloud Filter API sync-root cleanup."
    }

    if ($existingTask) {
        Write-Output "Removing the $taskName scheduled task..."
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    $dll = if (Test-Path $installedDll) {
        $installedDll
    } else {
        Resolve-BuildArtifact -FileName "yadorilink_shell_ext.dll"
    }
} else {
    $sourceDll = Resolve-BuildArtifact -FileName "yadorilink_shell_ext.dll" -Required
    $sourceCfapiHost = Resolve-BuildArtifact -FileName "yadorilink-cfapi-host.exe" -Required
    Write-Output "Installing shell-extension artifacts to $installDir..."
    Install-ProgramFilesArtifacts -SourceDll $sourceDll -SourceCfapiHost $sourceCfapiHost
    $dll = $installedDll
    $cfapiHost = $installedCfapiHost
}

if ($dll) {
    if (-not $Uninstall) {
        Assert-AdminOnlyWritableAcl -Path (Split-Path -Parent $dll) -RequireProtected
    }
    $regsvr32Args = @("/s")
    if ($Uninstall) {
        $regsvr32Args += "/u"
    }
    # Quote the DLL path ourselves: Start-Process's -ArgumentList does not
    # auto-quote array elements that contain spaces (and %ProgramFiles%
    # always contains one, "Program Files"), so an unquoted path here
    # would get split into multiple regsvr32 arguments and fail.
    $regsvr32Args += "`"$dll`""
    # Verified against a real Windows 11 VM: invoking regsvr32.exe via the
    # bare `&` call operator (`& regsvr32.exe @regsvr32Args`) left
    # $LASTEXITCODE unset ($null) here even though the registration/
    # unregistration itself succeeded (confirmed against the registry) —
    # `$null -ne 0` is true, so that pattern made this script report and
    # exit on a *successful* regsvr32 call as if it had failed. Using
    # Start-Process -Wait -PassThru and reading its own ExitCode property
    # gets a reliable result instead of depending on $LASTEXITCODE.
    $regsvr32Process = Start-Process -FilePath $regsvr32Exe -ArgumentList $regsvr32Args -Wait -NoNewWindow -PassThru
    if ($regsvr32Process.ExitCode -ne 0) {
        Write-Error "regsvr32.exe failed with exit code $($regsvr32Process.ExitCode)"
        exit $regsvr32Process.ExitCode
    }
} elseif ($Uninstall) {
    Write-Warning "Could not find yadorilink_shell_ext.dll; skipping COM unregistration."
} else {
    Write-Error "Could not find yadorilink_shell_ext.dll."
    exit 1
}

Write-Output "Restarting Explorer to pick up the change..."
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Start-Process -FilePath $explorerExe

if ($Uninstall) {
    Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction SilentlyContinue
} else {
    # Run yadorilink-cfapi-host as a Scheduled Task rather than a plain
    # background process: a process launched directly from an
    # installer/SSH-invoked shell can be torn down along with that
    # shell's session (Windows Job Object semantics), which would silently
    # kill sync-root registration/fetch-data handling soon after install
    # finishes. -LogonType Interactive runs it in the interactive user's
    # session (needed since Explorer/apps opening placeholders run there
    # too), independent of whatever shell launched this installer.
    Write-Output "Registering the $taskName scheduled task..."
    $action = New-ScheduledTaskAction -Execute $cfapiHost
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null

    Write-Output "Starting $taskName now..."
    Start-ScheduledTask -TaskName $taskName
}
