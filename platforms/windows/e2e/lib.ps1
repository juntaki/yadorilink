# Helpers for the Cloud Files end-to-end run (run-e2e.ps1). Dot-sourced; no side effects besides defining functions.
#
# Two real daemons run on one Windows machine. Device A has a Windows Cloud Files provider folder (served by the
# real yadorilink-cfapi-host). Device B has an ordinary directory. Both are members of one share. Nothing here
# drives a GUI: files are touched with ordinary file APIs, the CLI is the only control surface.

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class YlNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetCompressedFileSizeW(string name, out uint high);
    public static long AllocatedSize(string path) {
        uint high; uint low = GetCompressedFileSizeW(path, out high);
        if (low == 0xFFFFFFFF && Marshal.GetLastWin32Error() != 0) return -1;
        return ((long)high << 32) | low;
    }
}
'@ -ErrorAction SilentlyContinue

# ---- per-device environment ------------------------------------------------------------------------------------

$script:RealUserProfile = $env:USERPROFILE
$script:RealLocalAppData = $env:LOCALAPPDATA

# The host and the daemons keep their state in %LOCALAPPDATA%\yadorilink and put the sync root below
# %USERPROFILE%\YadoriLink. Both are moved into the work directory, so a run never reads or writes the real ones.
function Set-DeviceEnv([string]$Dev) {
    $env:LOCALAPPDATA = Join-Path $script:WorkDir "localappdata-$Dev"
    $env:USERPROFILE = Join-Path $script:WorkDir "profile-$Dev"
    Remove-Item Env:YADORILINK_PROVIDER_TEMP_ROOT -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $env:LOCALAPPDATA, $env:USERPROFILE | Out-Null
    $env:YADORILINK_CONFIG_DIR = Join-Path $script:WorkDir "cfg$Dev"
    $env:YADORILINK_CREDENTIAL_STORE = 'file'
    $env:YADORILINK_CONTROL_PIPE = "\\.\pipe\yl-e2e-$Dev-ctl"
    $env:YADORILINK_SHELL_IPC_PIPE = "\\.\pipe\yl-e2e-$Dev-shell"
    $env:YADORILINK_DEHYDRATE_PIPE = "\\.\pipe\yl-e2e-$Dev-dehydrate"
    $env:YADORILINK_HTTP_API_DISABLE = '1'
    $env:YADORILINK_COORDINATION_ADDR = $script:CoordinationAddr
    $env:YADORILINK_DISABLE_OS_KEYRING = '1'
    if (-not $env:RUST_LOG) { $env:RUST_LOG = 'info' }
    New-Item -ItemType Directory -Force $env:YADORILINK_CONFIG_DIR | Out-Null
}

function Invoke-Cli([string]$Dev, [string[]]$CliArgs) {
    Set-DeviceEnv $Dev
    $out = & $script:Cli @CliArgs 2>&1 | ForEach-Object { "$_" } | Out-String
    return $out.TrimEnd()
}

# ---- processes ---------------------------------------------------------------------------------------------------

$script:Procs = @{}
$script:LogPath = @{}
$script:LogSeq = 0

function Start-Component([string]$Key, [string]$Dev, [string]$Exe) {
    Set-DeviceEnv $Dev
    # One log pair per start: redirecting into an existing file would truncate what the previous instance wrote.
    $script:LogSeq++
    $tag = '{0}-{1:D3}-{2}' -f $Key, $script:LogSeq, (Get-Date -Format 'HHmmss')
    $log = Join-Path $script:LogDir "$tag.log"
    $err = Join-Path $script:LogDir "$tag.err.log"
    $script:LogPath[$Key] = $log
    $p = Start-Process -FilePath $Exe -RedirectStandardOutput $log -RedirectStandardError $err -WindowStyle Hidden -PassThru
    $script:Procs[$Key] = $p
    return $p
}

function Stop-Component([string]$Key) {
    $p = $script:Procs[$Key]
    if ($p -and -not $p.HasExited) {
        & taskkill.exe /F /T /PID $p.Id 2>&1 | Out-Null
        $null = $p.WaitForExit(15000)
    }
    $script:Procs.Remove($Key)
}

function Test-ComponentAlive([string]$Key) {
    $p = $script:Procs[$Key]
    return ($p -and -not $p.HasExited)
}

# The processes started from the two executables this run was given (and no others).
function Get-OwnProcesses {
    $own = @($script:Daemon, $script:HostExe)
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -in 'yadorilink-daemon.exe', 'yadorilink-cfapi-host.exe' -and $_.ExecutablePath -and ($own -contains $_.ExecutablePath)
    }
}

# A daemon or host that is not one of this run's executables is somebody's real installation: refuse to go on.
function Assert-NoForeignInstances {
    $own = @($script:Daemon, $script:HostExe)
    $foreign = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -in 'yadorilink-daemon.exe', 'yadorilink-cfapi-host.exe' -and ($own -notcontains $_.ExecutablePath)
    })
    if ($foreign.Count -gt 0) {
        throw ("another YadoriLink daemon or host is running ({0}); this run only stops its own processes and will not start next to it" -f (($foreign | ForEach-Object { "$($_.Name) $($_.ProcessId)" }) -join ', '))
    }
}

function Stop-AllComponents {
    foreach ($k in @($script:Procs.Keys)) { Stop-Component $k }
    # A previous run of this script (or a crashed one) may have left processes of its own executables behind.
    foreach ($p in @(Get-OwnProcesses)) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Wait-LogLine([string]$Key, [string]$Pattern, [int]$TimeoutSec = 60, [long]$FromOffset = 0) {
    $log = $script:LogPath[$Key]
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        if ($log -and (Test-Path $log)) {
            $text = Read-SharedText $log
            if ($text.Length -gt $FromOffset -and $text.Substring([int]$FromOffset) -match $Pattern) { return $true }
        }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

function Read-SharedText([string]$Path) {
    try {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite,Delete')
        try { $sr = New-Object IO.StreamReader($fs); return $sr.ReadToEnd() } finally { $fs.Dispose() }
    } catch { return '' }
}

# Length of a component's stdout log, to look only at what it printed after a point in time.
function Get-LogLength([string]$Key) {
    $p = $script:LogPath[$Key]
    if ($p -and (Test-Path $p)) { return (Read-SharedText $p).Length }
    return 0
}

# ---- waiting and comparing -------------------------------------------------------------------------------------

# Polls $Cond until it returns true. Returns the elapsed seconds, or $null on timeout. The budget is fixed per call
# site and is never widened to make a slow run pass.
function Wait-Until([scriptblock]$Cond, [int]$TimeoutSec = 90) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        $ok = $false
        try { $ok = [bool](& $Cond) } catch { $ok = $false }
        if ($ok) { return [math]::Round($sw.Elapsed.TotalSeconds, 1) }
        Start-Sleep -Milliseconds 400
    }
    return $null
}

function Get-Sha256([string]$Path) {
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite,Delete')
    try {
        $h = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($h.ComputeHash($fs)) -replace '-', '').ToLowerInvariant() } finally { $h.Dispose() }
    } finally { $fs.Dispose() }
}

function Get-TextNoBom([string]$Path) {
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite,Delete')
    try { $sr = New-Object IO.StreamReader($fs, (New-Object Text.UTF8Encoding($false))); return $sr.ReadToEnd() } finally { $fs.Dispose() }
}

function Set-RandomFile([string]$Path, [long]$Size, [int]$Seed) {
    $rng = New-Object Random $Seed
    $buf = New-Object byte[] (1MB)
    $fs = [IO.File]::Create($Path)
    try {
        $left = $Size
        while ($left -gt 0) {
            $n = [int][math]::Min($left, $buf.Length)
            $rng.NextBytes($buf)
            $fs.Write($buf, 0, $n)
            $left -= $n
        }
    } finally { $fs.Dispose() }
}

# Overwrites $Length bytes at $Offset with pseudo-random data, leaving the file size unchanged.
function Update-FileRange([string]$Path, [long]$Offset, [int]$Length, [int]$Seed) {
    $buf = New-Object byte[] $Length
    (New-Object Random $Seed).NextBytes($buf)
    $fs = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'ReadWrite,Delete')
    try { $null = $fs.Seek($Offset, 'Begin'); $fs.Write($buf, 0, $Length) } finally { $fs.Dispose() }
}

function Get-RangeHash([string]$Path, [long]$Offset, [int]$Length) {
    $buf = New-Object byte[] $Length
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite,Delete')
    try {
        $null = $fs.Seek($Offset, 'Begin')
        $got = 0
        while ($got -lt $Length) { $n = $fs.Read($buf, $got, $Length - $got); if ($n -le 0) { break }; $got += $n }
    } finally { $fs.Dispose() }
    $h = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($buf, 0, $got)) -replace '-', '').ToLowerInvariant() } finally { $h.Dispose() }
}

# ---- placeholder facts -----------------------------------------------------------------------------------------

$script:RECALL_ON_DATA_ACCESS = 0x400000
$script:REPARSE_POINT = 0x400

function Get-Attrs([string]$Path) { return [int](Get-Item -LiteralPath $Path -Force).Attributes }

# A Cloud Files placeholder: a reparse point that recalls data on access (the file is not fully present).
function Test-Placeholder([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $a = Get-Attrs $Path
    return (($a -band $script:REPARSE_POINT) -ne 0) -and (($a -band $script:RECALL_ON_DATA_ACCESS) -ne 0)
}

# What the operating system says about a file in the sync root: "placeholder" (data is recalled on access),
# "hydrated" (a placeholder or file whose data is all on disk), or "other".
function Get-LocalState([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return 'missing' }
    $item = Get-Item -LiteralPath $Path -Force
    $a = [int]$item.Attributes
    if ($a -band $script:RECALL_ON_DATA_ACCESS) { return 'placeholder' }
    if ($item.Length -eq 0) { return 'hydrated' }
    $alloc = [YlNative]::AllocatedSize($Path)
    if ($alloc -ge $item.Length) { return 'hydrated' }
    return "other(attrs=$a,alloc=$alloc)"
}

function Get-TreeSnapshot([string]$Root) {
    $rows = Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $rel = $_.FullName.Substring($Root.Length)
        # The daemon keeps its own marker files in the root of an ordinary shared folder.
        if ($rel -like '\.yadorilink*') { return }
        $len = if ($_.PSIsContainer) { 0 } else { $_.Length }
        "$rel|$len"
    }
    return ($rows | Sort-Object) -join "`n"
}
