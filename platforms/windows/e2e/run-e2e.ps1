# Cloud Files end-to-end run against the real binaries. Runs ON the Windows machine under test.
#
#   Device A  a Windows Cloud Files provider folder, served by the real yadorilink-cfapi-host (a placeholder tree
#             backed by the daemon, hydrated on demand through CfAPI).
#   Device B  an ordinary directory synced by the second daemon.
#   Both daemons run on this machine, join one share and talk through a coordination service reachable at
#   -CoordinationAddr. No GUI is driven: every file operation is an ordinary file API call from this script, and
#   every assertion looks at bytes (SHA-256), names, sizes and placeholder attributes.
#
# Scenarios (numbers are stable and used by -Scenarios):
#    1 placeholder creation            8 evict (dehydrate through the daemon's Full-custody check)
#    2 open/read hydrates              9 reopen rehydrates
#    3 content equals the remote bytes (multi-block) 10 daemon / host restart while a hydration is in flight
#    4 edit and save on Windows        11 host restart
#    5 rename on Windows               12 daemon restart
#    6 delete on Windows               13 Windows reboot (needs the driver, see below)
#    7 remote modify shows up on Windows
#   17 (only with -OnDemandObserver) the on-demand external observer: allocated bytes of the folder and of the block store, first-open latency
#   15 a local edit during a hydration is kept and shared
#   16 a change made on the other device during a hydration wins
#   14 (clean-up) the remote delete of the iteration directory reaches Windows
#
# Reboot. Scenario 13 restarts the guest operating system, which ends this script. It stores what it needs in
# <WorkDir>\state.json, requests `shutdown /r`, and exits with code 75. It only does so when the machine was declared
# dedicated to these runs (-RebootMarker file exists); otherwise the scenario is reported as not run. Run the SAME command again once the machine
# is back (drive-remote.sh does that over ssh): the run continues from the stored state, verifies the post-reboot
# state, and carries on with the remaining iterations. Pass -SkipReboot to leave scenario 13 out.
#
# USAGE (Windows PowerShell 5.1)
#   .\run-e2e.ps1 -BinDir .\target\release -HostExe .\platforms\windows\shell\target\debug\yadorilink-cfapi-host.exe `
#       -CoordinationAddr http://127.0.0.1:8788 -AuthDriver <sign-in helper> -Iterations 10 -Fresh
#
# The cfapi-host must be a debug build: only a debug build lets this script give it its own pipe names, so that the
# two daemons on one machine do not collide.
#
# -AuthDriver is the sign-in helper for the test coordination service: a Python script taking
#   login --addr <coordination address> --subject <subject> -- <cli command>
# which completes the CLI's `login --device` flow as that subject (no browser). Python 3 must be on PATH.
#
# Exit codes: 0 all green, 1 at least one check failed, 2 setup failed, 75 reboot requested (run again).
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BinDir,
    [Parameter(Mandatory = $true)][string]$HostExe,
    [Parameter(Mandatory = $true)][string]$CoordinationAddr,
    [string]$AuthDriver = '',
    [string]$WorkDir = (Join-Path $env:USERPROFILE 'cfapi-e2e'),
    [int]$Iterations = 1,
    # Comma separated scenario numbers to run, e.g. "1,8,9" (scenario 1 creates the files the others use).
    [string]$Scenarios = '',
    [int]$HoldMB = 96,
    [int]$RaceMB = 64,
    [int]$SyncTimeoutSec = 90,
    # The account both devices sign in as. A fresh run uses a new one unless this is given: an account only takes so many devices.
    [string]$Subject = '',
    [switch]$Fresh,
    [switch]$SkipReboot,
    # Scenario 17: the on-demand external-observer measurement (allocated bytes before hydration, after it and after an
    # evict; first-open latency) on this provider folder, run by this Python script. Not part of a default run.
    [string]$OnDemandObserver = '',
    # The full corpus (4 KiB x 200, 1 MiB x 200, 1 GiB x 1) instead of the smoke corpus.
    [switch]$ObserverFullCorpus,
    # Scenario 13 restarts the whole machine. It only runs when this file exists, i.e. when somebody declared the
    # machine to be dedicated to these runs.
    [string]$RebootMarker = (Join-Path $env:ProgramData 'yadorilink-e2e-machine.marker')
)

$Only = @(if ($Scenarios) { $Scenarios -split ',' | ForEach-Object { [int]$_ } })
# Only a directory this script made (or an empty one) is ever wiped.
New-Item -ItemType Directory -Force $WorkDir | Out-Null
$workMarker = Join-Path $WorkDir '.cfapi-e2e-workdir'
if (-not (Test-Path $workMarker)) {
    if (@(Get-ChildItem -LiteralPath $WorkDir -Force).Count -ne 0) { Write-Host "$WorkDir is not empty and was not made by this script; use another -WorkDir"; exit 2 }
    'cfapi-e2e work directory' | Set-Content $workMarker
}
$script:WorkDir = (Resolve-Path $WorkDir).Path
$script:CoordinationAddr = $CoordinationAddr
$script:LogDir = (New-Item -ItemType Directory -Force (Join-Path $script:WorkDir 'logs')).FullName
. (Join-Path $PSScriptRoot 'lib.ps1')

$script:Cli = Join-Path (Resolve-Path $BinDir).Path 'yadorilink.exe'
$script:Daemon = Join-Path (Resolve-Path $BinDir).Path 'yadorilink-daemon.exe'
$script:HostExe = (Resolve-Path $HostExe).Path
$script:StatePath = Join-Path $script:WorkDir 'state.json'
$script:B = Join-Path $script:WorkDir 'folderB'
$script:Stage = Join-Path $script:WorkDir 'stage'
$script:Timeout = $SyncTimeoutSec
$script:HoldBytes = [long]$HoldMB * 1MB
$script:RaceBytes = [long]$RaceMB * 1MB
$script:Failed = 0
$script:RebootSkipped = $false

# ---- state -----------------------------------------------------------------------------------------------------

function Save-State { $script:State | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 $script:StatePath }

function Add-Result([int]$Iter, [int]$No, [string]$Name, [bool]$Ok, [double]$Secs, [string]$Detail) {
    $script:State.results += [pscustomobject]@{ iteration = $Iter; scenario = $No; name = $Name; ok = $Ok; seconds = $Secs; detail = $Detail }
    Save-State
    $tag = if ($Ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] it{1:D2} S{2:D2} {3,-34} {4,6:N1}s  {5}" -f $tag, $Iter, $No, $Name, $Secs, $Detail)
    if (-not $Ok) { $script:Failed++ }
}

function Assert-That([bool]$Cond, [string]$Message) { if (-not $Cond) { throw $Message } }

function Save-FailureLogs([int]$Iter, [int]$No) {
    $dir = Join-Path $script:WorkDir ("failures\it{0:D2}-S{1:D2}" -f $Iter, $No)
    New-Item -ItemType Directory -Force $dir | Out-Null
    foreach ($f in Get-ChildItem $script:LogDir -Filter *.log -ErrorAction SilentlyContinue) {
        $t = Read-SharedText $f.FullName
        $lines = $t -split "`n"
        ($lines | Select-Object -Last 150) -join "`n" | Set-Content -Encoding utf8 (Join-Path $dir $f.Name)
    }
    try { Invoke-Cli 'a' @('status') | Set-Content -Encoding utf8 (Join-Path $dir 'status-a.txt') } catch {}
    try { Invoke-Cli 'b' @('status') | Set-Content -Encoding utf8 (Join-Path $dir 'status-b.txt') } catch {}
    try { Get-TreeSnapshot $script:A | Set-Content -Encoding utf8 (Join-Path $dir 'tree-a.txt') } catch {}
    try { Get-TreeSnapshot $script:B | Set-Content -Encoding utf8 (Join-Path $dir 'tree-b.txt') } catch {}
}

function Invoke-Scenario([int]$Iter, [int]$No, [string]$Name, [scriptblock]$Body, [switch]$RecordOnlyFailure) {
    if ($Only.Count -gt 0 -and $Only -notcontains $No) { return }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $ok = $true; $detail = ''
    try { $detail = [string](& $Body | Select-Object -Last 1) } catch { $ok = $false; $detail = $_.Exception.Message }
    if ($ok -and $RecordOnlyFailure) { Write-Host "   $Name`: $detail"; return }
    Add-Result $Iter $No $Name $ok $sw.Elapsed.TotalSeconds $detail
    if (-not $ok) { Save-FailureLogs $Iter $No }
}

# ---- setup and process control ---------------------------------------------------------------------------------

function Start-Daemons {
    $null = Start-Component 'daemonB' 'b' $script:Daemon
    $null = Start-Component 'daemonA' 'a' $script:Daemon
    Assert-That ($null -ne (Wait-Until { (Invoke-Cli 'a' @('status')) -notmatch 'not running|could not connect|refused' } 60)) 'daemon A did not answer'
    Assert-That ($null -ne (Wait-Until { (Invoke-Cli 'b' @('status')) -notmatch 'not running|could not connect|refused' } 60)) 'daemon B did not answer'
}

function Start-CfapiHost {
    $null = Start-Component 'host' 'a' $script:HostExe
    Assert-That (Wait-LogLine 'host' 'showing \d+ item\(s\)' 90) 'cfapi-host never showed the namespace'
}

function Wait-ProviderReady {
    $r = Wait-Until { (Invoke-Cli 'a' @('status')) -match 'provider folder .*: ready' } 90
    Assert-That ($null -ne $r) 'daemon A never reported the provider folder ready'
}

function Assert-CoordinationReachable {
    $url = "$($script:CoordinationAddr.TrimEnd('/'))/.well-known/openid-configuration"
    $ok = Wait-Until { (Invoke-WebRequest -UseBasicParsing $url -TimeoutSec 5).StatusCode -eq 200 } 60
    Assert-That ($null -ne $ok) "the coordination service is not reachable at $($script:CoordinationAddr)"
}

function Initialize-Run {
    Write-Host '== setup: two devices, one share, one provider folder'
    Assert-CoordinationReachable
    Assert-NoForeignInstances
    Stop-AllComponents
    Start-Sleep 2
    # Take the previous run's sync roots out of the registry of Windows before their folders go.
    # The registry is published as generation files (cfapi_sync_roots.txt.<seq>).
    $oldRegistry = Join-Path $script:WorkDir 'localappdata-a\yadorilink\cfapi_sync_roots.txt.*'
    if (Test-Path $oldRegistry) { Set-DeviceEnv 'a'; & $script:HostExe --unregister-all 2>&1 | Out-Null }
    foreach ($d in 'localappdata-a', 'localappdata-b', 'profile-a', 'profile-b', 'cfga', 'cfgb', 'folderB', 'stage', 'logs', 'failures', 'hold') { Remove-Item -Recurse -Force (Join-Path $script:WorkDir $d) -ErrorAction SilentlyContinue }
    foreach ($d in 'cfga', 'cfgb', 'folderB') { Assert-That (-not (Test-Path (Join-Path $script:WorkDir $d))) "could not remove the previous run's $d (a process still holds it)" }
    New-Item -ItemType Directory -Force $script:LogDir, $script:B, $script:Stage | Out-Null
    if (-not $Subject) { $script:Subject = "cfapi-e2e-$([DateTime]::Now.ToString('yyyyMMddHHmmss'))" } else { $script:Subject = $Subject }
    foreach ($dev in 'a', 'b') {
        Set-DeviceEnv $dev
        Assert-That ($AuthDriver -ne '') '-AuthDriver is required for a fresh run'
        # The sign-in helper is not part of what is tested: it runs with the real profile.
        $env:USERPROFILE = $script:RealUserProfile; $env:LOCALAPPDATA = $script:RealLocalAppData
        $o = & python $AuthDriver login --addr $script:CoordinationAddr --subject $script:Subject --timeout 120 --attempts 3 -- $script:Cli 2>&1 | Out-String
        Assert-That ($o -match 'logged-in') "sign-in of device $dev failed: $o"
        $o = Invoke-Cli $dev @('device', 'register', '--name', "cfapi-e2e-$dev")
        Assert-That ($o -match 'Registered device') "device $dev registration failed: $o"
    }
    $null = Start-Component 'daemonB' 'b' $script:Daemon
    $null = Start-Component 'daemonA' 'a' $script:Daemon
    Assert-That ($null -ne (Wait-Until { (Invoke-Cli 'b' @('status')) -notmatch 'not running|could not connect|refused' } 60)) 'daemon B did not answer'
    Set-Content -Encoding ascii (Join-Path $script:B 'seed.txt') 'seed'
    # A daemon answers its control pipe before it has loaded its device identity; retry only that start-up refusal.
    $o = ''
    $null = Wait-Until { $script:o = Invoke-Cli 'b' @('share', 'create', 'cfapi-e2e', '--path', $script:B, '--yes'); $script:o -notmatch 'identity is unavailable' } 60
    $o = $script:o
    Assert-That ($o -match 'Created folder group (\S+)') "share create failed: $o"
    $group = $Matches[1]
    $display = "E2E$([DateTime]::Now.ToString('MMddHHmmss'))"
    $null = Wait-Until { $script:o = Invoke-Cli 'a' @('provider-folder', 'join', $group, $display, '--on-demand'); $script:o -notmatch 'identity is unavailable' } 60
    $o = $script:o
    Assert-That ($o -match 'Created provider folder') "provider-folder join failed: $o"
    $script:State = [pscustomobject]@{ group = $group; display = $display; next_iteration = 1; results = @(); pending = $null; started = (Get-Date -Format o) }
    Save-State
    $script:A = Join-Path (Join-Path (Join-Path $script:WorkDir 'profile-a') 'YadoriLink') $display
    Start-CfapiHost
    Wait-ProviderReady
    Assert-That ($null -ne (Wait-Until { Test-Path (Join-Path $script:A 'seed.txt') } $script:Timeout)) 'the first placeholder never appeared'
    Write-Host "   share $group, provider folder $display at $script:A"
}

# After a daemon start, sync with the other device is not fully up for a while: changes made on the other side do not
# arrive, the other side's fetches of blocks of new files are answered "not found" (it retries for 40 s), and an unread
# placeholder may be refused with "no reachable peer". `yadorilink status` shows the end of that period (a connected
# peer and no "cannot fetch now"); on the machines tried it took about 88 s after every start. Waits (bounded) for it
# and returns the seconds, which the scenarios report.
function Wait-SyncReady([int]$TimeoutSec = 180) {
    $t = Wait-Until { $o = Invoke-Cli 'a' @('status'); ($o -match '(?ms)Peers:.*connected') -and ($o -notmatch 'cannot fetch now') } $TimeoutSec
    Assert-That ($null -ne $t) "daemon A was not ready to sync $TimeoutSec s after it started"
    return $t
}

function Resume-Run {
    Write-Host '== resume: starting daemons and host'
    Assert-CoordinationReachable
    Assert-NoForeignInstances
    Stop-AllComponents
    Start-Sleep 2
    Start-Daemons
    Start-CfapiHost
    Wait-ProviderReady
}

# ---- scenario helpers ------------------------------------------------------------------------------------------

function New-Seed([string]$Name, [string]$Kind, $Spec, [int]$Seed) {
    $stagePath = Join-Path $script:Stage ([IO.Path]::GetRandomFileName())
    if ($Kind -eq 'text') { [IO.File]::WriteAllText($stagePath, [string]$Spec, (New-Object Text.UTF8Encoding($false))) } else { Set-RandomFile $stagePath ([long]$Spec) $Seed }
    $dest = Join-Path $script:ItB $Name
    New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null
    Move-Item -LiteralPath $stagePath -Destination $dest
    return $dest
}

function Wait-RemoteHash([string]$APath, [string]$Expected, [int]$Timeout) {
    return Wait-Until { (Test-Path -LiteralPath $APath) -and ((Get-Sha256 $APath) -eq $Expected) } $Timeout
}

function Wait-RemoteText([string]$BPath, [string]$Expected, [int]$Timeout) {
    return Wait-Until { (Test-Path -LiteralPath $BPath) -and ((Get-TextNoBom $BPath) -eq $Expected) } $Timeout
}

function Wait-RemoteSame([string]$APath, [string]$BPath, [int]$Timeout) {
    return Wait-Until { (Test-Path -LiteralPath $BPath) -and ((Get-Sha256 $BPath) -eq (Get-Sha256 $APath)) } $Timeout
}

function Test-NamespaceConverged {
    # The same set of names and sizes on both sides; ignores the daemon-private bookkeeping files of the share root.
    $a = Get-TreeSnapshot $script:A
    $b = Get-TreeSnapshot $script:B
    return ($a -eq $b)
}

# ---- scenarios -------------------------------------------------------------------------------------------------

function Invoke-Iteration([int]$Iter) {
    $n = '{0:D2}' -f $Iter
    $script:It = "it$n"
    $script:ItA = Join-Path $script:A $script:It
    $script:ItB = Join-Path $script:B $script:It
    $script:Ctx = @{}
    Write-Host "== iteration $Iter"
    $A = $script:ItA; $B = $script:ItB; $Tmo = $script:Timeout
    $tok = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $c = $script:Ctx

    Invoke-Scenario $Iter 1 'placeholder creation' {
        $c.big = (New-Seed 'big.bin' 'rand' 5300017 ($Iter * 100 + 1))
        $c.seek = (New-Seed 'seek.bin' 'rand' 4500011 ($Iter * 100 + 2))
        $c.editbig = (New-Seed 'editbig.bin' 'rand' 4194304 ($Iter * 100 + 3))
        $c.remotebig = (New-Seed 'remotebig.bin' 'rand' 4194304 ($Iter * 100 + 4))
        $c.evict = (New-Seed 'evict.bin' 'rand' 3700003 ($Iter * 100 + 5))
        $c.evict2 = (New-Seed 'evict2.bin' 'rand' 3600007 ($Iter * 100 + 12))
        $texts = @{
            'read.txt' = "read $tok - $([string]::new([char]0x65E5, 3))`r`nsecond line"; 'edit.txt' = "edit-base $tok"; 'ren.txt' = "rename me $tok"; 'renph.txt' = "rename placeholder $tok"
            'del.txt' = "delete me $tok"; 'delph.txt' = "delete placeholder $tok"; 'remote.txt' = "remote base $tok"; 'remote2.txt' = "remote2 base $tok"
            'deldir\a.txt' = "a $tok"; 'deldir\sub\b.txt' = "b $tok"; 'docs\notes.txt' = "notes $tok"
        }
        foreach ($k in $texts.Keys) { $null = New-Seed $k 'text' $texts[$k] 0 }
        $c.read = Join-Path $B 'read.txt'
        $c.hold1 = (New-Seed 'hold1.bin' 'rand' $script:HoldBytes ($Iter * 100 + 6))
        $c.hold2 = (New-Seed 'hold2.bin' 'rand' $script:HoldBytes ($Iter * 100 + 7))
        $c.rest = (New-Seed 'restart.bin' 'rand' 3300001 ($Iter * 100 + 8))
                $c.holdSha1 = Get-Sha256 $c.hold1; $c.holdSha2 = Get-Sha256 $c.hold2
        $c.race1 = (New-Seed 'race1.bin' 'rand' $script:RaceBytes ($Iter * 100 + 13))
        $c.race2 = (New-Seed 'race2.bin' 'rand' $script:RaceBytes ($Iter * 100 + 14))
        $c.overwrite = (New-Seed 'overwrite.bin' 'rand' 3100003 ($Iter * 100 + 15))
        $c.race1Sha = Get-Sha256 $c.race1; $c.race2Sha = Get-Sha256 $c.race2
        $c.race1Head = Get-RangeHash $c.race1 0 1000000; $c.race1Tail = Get-RangeHash $c.race1 1004096 ($script:RaceBytes - 1004096)
        $c.bigSha = Get-Sha256 $c.big; $c.restSha = Get-Sha256 $c.rest
        $expect = Get-ChildItem -LiteralPath $B -Recurse -File
        $t = Wait-Until { $all = $true; foreach ($f in $expect) { $p = Join-Path $A $f.FullName.Substring($B.Length + 1); if (-not ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Length -eq $f.Length))) { $all = $false; break } }; $all } $Tmo
        Assert-That ($null -ne $t) 'not every file appeared on A with the right size'
        $bad = @($expect | Where-Object { -not (Test-Placeholder (Join-Path $A $_.FullName.Substring($B.Length + 1))) })
        Assert-That ($bad.Count -eq 0) ("not a placeholder on A: " + (($bad | ForEach-Object Name) -join ', '))
        $w = Get-LocalState (Join-Path $A 'read.txt')
        Assert-That ($w -eq 'placeholder') "read.txt is '$w' before any read"
        "$($expect.Count) placeholders in ${t}s"
    }

    Invoke-Scenario $Iter 2 'open/read hydrates' {
        $p = Join-Path $A 'read.txt'
        $got = (Get-Content -LiteralPath $p -Raw -Encoding UTF8)
        $want = (Get-TextNoBom (Join-Path $B 'read.txt'))
        Assert-That ($got -ceq $want) "read.txt differs: [$got] vs [$want]"
        $t = Wait-Until { (Get-LocalState $p) -eq 'hydrated' } 30
        Assert-That ($null -ne $t) "read.txt is '$(Get-LocalState $p)' after the read"
        "hydrated after the read"
    }

    Invoke-Scenario $Iter 3 'content equals remote (multi-block)' {
        $pb = Join-Path $A 'big.bin'
        $h = (Get-FileHash -LiteralPath $pb -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-That ($h -eq $c.bigSha) "big.bin ($((Get-Item -LiteralPath $pb).Length) bytes) hash $h expected $($c.bigSha)"
        $ps = Join-Path $A 'seek.bin'
        $rangeWant = Get-RangeHash (Join-Path $B 'seek.bin') 3500000 4096
        $rangeGot = Get-RangeHash $ps 3500000 4096
        Assert-That ($rangeGot -eq $rangeWant) 'ranged read inside seek.bin differs'
        Assert-That ((Get-Sha256 $ps) -eq (Get-Sha256 (Join-Path $B 'seek.bin'))) 'seek.bin full hash differs'
        "big.bin $((Get-Item -LiteralPath $pb).Length) bytes and seek.bin identical"
    }

    Invoke-Scenario $Iter 4 'edit/save on Windows' {
        $p = Join-Path $A 'edit.txt'
        $null = Get-Content -LiteralPath $p -Raw
        [IO.File]::AppendAllText($p, " + edited on A $tok", (New-Object Text.UTF8Encoding($false)))
        $want = "edit-base $tok + edited on A $tok"
        $t = Wait-RemoteText (Join-Path $B 'edit.txt') $want $Tmo
        Assert-That ($null -ne $t) "B never got the edit; B has [$(Get-TextNoBom (Join-Path $B 'edit.txt'))]"
        $pe = Join-Path $A 'editbig.bin'
        $null = Get-Sha256 $pe
        Update-FileRange $pe 1500000 4096 ($Iter * 7)
        $aHash = Get-Sha256 $pe
        $t2 = Wait-Until { (Get-Sha256 (Join-Path $B 'editbig.bin')) -eq $aHash } $Tmo
        Assert-That ($null -ne $t2) 'B never got the range edit of editbig.bin'
        # An editor's save: write a temp file and replace the original.
        $pr = Join-Path $A 'docs\notes.txt'
        $null = Get-Content -LiteralPath $pr -Raw
        $tmp = Join-Path $A 'docs\notes.tmp'
        [IO.File]::WriteAllText($tmp, "saved by replacing $tok", (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $tmp -Destination $pr -Force
        $t3 = Wait-RemoteText (Join-Path $B 'docs\notes.txt') "saved by replacing $tok" $Tmo
        Assert-That ($null -ne $t3) 'B never got the save-by-replace'
        Assert-That (-not (Test-Path -LiteralPath (Join-Path $B 'docs\notes.tmp'))) 'the temp file reached B'
        # The whole content of a placeholder that was never read is replaced. Nothing YadoriLink handed to Windows proves
        # where those bytes come from, so the remote version stays the item and the new bytes are kept beside it as a
        # conflicted copy, on both devices. They are never lost and never silently replace the remote content.
        $po = Join-Path $A 'overwrite.bin'
        $fresh = New-Object byte[] 2500001; (New-Object Random ($Iter * 31)).NextBytes($fresh)
        [IO.File]::WriteAllBytes($po, $fresh)
        $freshHash = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($fresh)) -replace '-', '').ToLowerInvariant()
        $copyOn = { param($dir) @(Get-ChildItem -LiteralPath $dir -Filter 'overwrite (conflicted copy*).bin' -ErrorAction SilentlyContinue) }
        $t4 = Wait-Until { (@(& $copyOn $A).Count -eq 1) -and (@(& $copyOn $B).Count -eq 1) } $Tmo
        Assert-That ($null -ne $t4) 'the bytes written over an unread placeholder were not kept as a conflicted copy on both devices'
        Assert-That ((Get-Sha256 (& $copyOn $B)[0].FullName) -eq $freshHash) 'the conflicted copy on B does not hold the written bytes'
        Assert-That ((Get-Sha256 (& $copyOn $A)[0].FullName) -eq $freshHash) 'the conflicted copy on A does not hold the written bytes'
        Assert-That ((Get-Sha256 (Join-Path $B 'overwrite.bin')) -eq (Get-Sha256 $c.overwrite)) 'overwrite.bin on B no longer holds its own bytes'
        $t5 = Wait-RemoteHash $po (Get-Sha256 $c.overwrite) $Tmo
        Assert-That ($null -ne $t5) 'overwrite.bin on A does not read as the remote version again'
        "text ${t}s, ranged ${t2}s, replace ${t3}s, bytes written over an unread placeholder kept as a conflicted copy in ${t4}s"
    }

    Invoke-Scenario $Iter 5 'rename' {
        $null = Get-Content -LiteralPath (Join-Path $A 'ren.txt') -Raw
        Rename-Item -LiteralPath (Join-Path $A 'ren.txt') -NewName 'ren2.txt'
        $t = Wait-Until { (Test-Path -LiteralPath (Join-Path $B 'ren2.txt')) -and -not (Test-Path -LiteralPath (Join-Path $B 'ren.txt')) } $Tmo
        Assert-That ($null -ne $t) 'B never saw the rename of a hydrated file'
        Assert-That ((Get-TextNoBom (Join-Path $B 'ren2.txt')) -ceq "rename me $tok") 'renamed file content changed'
        Rename-Item -LiteralPath (Join-Path $A 'renph.txt') -NewName 'renph2.txt'
        $t2 = Wait-Until { (Test-Path -LiteralPath (Join-Path $B 'renph2.txt')) -and -not (Test-Path -LiteralPath (Join-Path $B 'renph.txt')) } $Tmo
        Assert-That ($null -ne $t2) 'B never saw the rename of a placeholder'
        Assert-That ((Get-Content -LiteralPath (Join-Path $A 'renph2.txt') -Raw) -ceq "rename placeholder $tok") 'renamed placeholder reads differently'
        Rename-Item -LiteralPath (Join-Path $A 'deldir\sub') -NewName 'sub2'
        $t3 = Wait-Until { (Test-Path -LiteralPath (Join-Path $B 'deldir\sub2\b.txt')) -and -not (Test-Path -LiteralPath (Join-Path $B 'deldir\sub')) } $Tmo
        Assert-That ($null -ne $t3) 'B never saw the rename of a directory'
        "hydrated ${t}s, placeholder ${t2}s, directory ${t3}s"
    }

    Invoke-Scenario $Iter 6 'delete' {
        $null = Get-Content -LiteralPath (Join-Path $A 'del.txt') -Raw
        Remove-Item -LiteralPath (Join-Path $A 'del.txt')
        Remove-Item -LiteralPath (Join-Path $A 'delph.txt')
        $t = Wait-Until { -not (Test-Path -LiteralPath (Join-Path $B 'del.txt')) -and -not (Test-Path -LiteralPath (Join-Path $B 'delph.txt')) } $Tmo
        Assert-That ($null -ne $t) 'B still has a deleted file'
        Remove-Item -LiteralPath (Join-Path $A 'deldir') -Recurse -Force
        $t2 = Wait-Until { -not (Test-Path -LiteralPath (Join-Path $B 'deldir')) } $Tmo
        Assert-That ($null -ne $t2) 'B still has the deleted directory'
        Assert-That (-not (Test-Path -LiteralPath (Join-Path $A 'deldir'))) 'the deleted directory came back on A'
        "files ${t}s, directory ${t2}s"
    }

    Invoke-Scenario $Iter 7 'remote modify reflected' {
        $pr = Join-Path $A 'remote.txt'
        $null = Get-Content -LiteralPath $pr -Raw
        [IO.File]::AppendAllText((Join-Path $B 'remote.txt'), " + changed on B $tok", (New-Object Text.UTF8Encoding($false)))
        $t = Wait-Until { (Get-TextNoBom $pr) -ceq "remote base $tok + changed on B $tok" } $Tmo
        Assert-That ($null -ne $t) "A still reads [$(Get-Content -LiteralPath $pr -Raw)]"
        [IO.File]::WriteAllText((Join-Path $B 'remote2.txt'), "remote2 rewritten $tok", (New-Object Text.UTF8Encoding($false)))
        $p2 = Join-Path $A 'remote2.txt'
        $t2 = Wait-Until { (Get-TextNoBom $p2) -ceq "remote2 rewritten $tok" } $Tmo
        Assert-That ($null -ne $t2) "A still reads [$(Get-Content -LiteralPath $p2 -Raw)] for a placeholder rewritten on B"
        $pb = Join-Path $A 'remotebig.bin'
        $null = Get-Sha256 $pb
        Update-FileRange (Join-Path $B 'remotebig.bin') 2000000 8192 ($Iter * 11)
        $want = Get-Sha256 (Join-Path $B 'remotebig.bin')
        $t3 = Wait-RemoteHash $pb $want $Tmo
        Assert-That ($null -ne $t3) 'A never read the changed remotebig.bin'
        [IO.File]::WriteAllText((Join-Path $B 'newremote.txt'), "created on B $tok", (New-Object Text.UTF8Encoding($false)))
        $t4 = Wait-Until { (Test-Path -LiteralPath (Join-Path $A 'newremote.txt')) -and ((Get-TextNoBom (Join-Path $A 'newremote.txt')) -ceq "created on B $tok") } $Tmo
        Assert-That ($null -ne $t4) 'a file created on B never appeared on A'
        "hydrated ${t}s, placeholder ${t2}s, multi-block ${t3}s, new file ${t4}s"
    }

    Invoke-Scenario $Iter 8 'evict (Full-custody check)' {
        $p = Join-Path $A 'evict.bin'
        $want = Get-Sha256 (Join-Path $B 'evict.bin')
        Assert-That ((Get-Sha256 $p) -eq $want) 'evict.bin differs before the eviction'
        $sizeBefore = (Get-Item -LiteralPath $p).Length
        $script:attempts = 0; $script:out = ''
        # The daemon drops the copy only for an item it has heard the host report as materialized after the
        # handoff (a poll or two after the read), so the first attempts may be answered 'not evicted'.
        $t = Wait-Until { $script:attempts++; $script:out = Invoke-Cli 'a' @('evict', $p); $script:out -cmatch '^Evicted ' } 60
        $attempts = $script:attempts; $out = $script:out
        Assert-That ($null -ne $t) "evict never succeeded: $out"
        $t2 = Wait-Until { (Get-LocalState $p) -eq 'placeholder' } 30
        Assert-That ($null -ne $t2) "after the eviction: state=$(Get-LocalState $p)"
        $alloc = [YlNative]::AllocatedSize($p)
        Assert-That ($alloc -ge 0 -and $alloc -lt 65536) "still $alloc bytes allocated on disk after the eviction"
        Assert-That ((Get-Item -LiteralPath $p).Length -eq $sizeBefore) 'the logical size changed with the eviction'
        # A file with a local edit that has not been shared yet must not be dropped.
        $p2 = Join-Path $A 'evict2.bin'
        $null = Get-Sha256 $p2
        $fs = [IO.File]::Open($p2, 'Append', 'Write', 'ReadWrite,Delete'); $fs.Write([byte[]](1, 2, 3, 4), 0, 4); $fs.Dispose()
        $refusal = Invoke-Cli 'a' @('evict', $p2)
        Assert-That ($refusal -cnotmatch '^Evicted ') "an unshared local edit was evicted: $refusal"
        Assert-That ((Get-Item -LiteralPath $p2).Length -eq 3600011) 'the unshared edit is gone from the file'
        $t3 = Wait-Until { (Get-Item -LiteralPath (Join-Path $B 'evict2.bin')).Length -eq 3600011 -and (Get-Sha256 (Join-Path $B 'evict2.bin')) -eq (Get-Sha256 $p2) } $Tmo
        Assert-That ($null -ne $t3) 'the edit refused for eviction never reached B'
        "evicted after $attempts attempt(s), placeholder in ${t2}s, allocated $alloc bytes; unshared edit kept and shared in ${t3}s"
    }

    Invoke-Scenario $Iter 9 'reopen rehydrates' {
        $p = Join-Path $A 'evict.bin'
        $want = Get-Sha256 (Join-Path $B 'evict.bin')
        Assert-That ((Get-Sha256 $p) -eq $want) 'evict.bin differs after the rehydration'
        $t = Wait-Until { (Get-LocalState $p) -eq 'hydrated' } 30
        Assert-That ($null -ne $t) "state is '$(Get-LocalState $p)' after the reopen"
        $alloc = [YlNative]::AllocatedSize($p)
        Assert-That ($alloc -ge (Get-Item -LiteralPath $p).Length) "only $alloc bytes allocated after a full read"
        "rehydrated, $alloc bytes on disk"
    }

    Invoke-Scenario $Iter 10 'restart during hydration' {
        $r1 = Test-RestartDuringRead 'host' (Join-Path $A 'hold1.bin') $c.holdSha1
        $r2 = Test-RestartDuringRead 'daemonA' (Join-Path $A 'hold2.bin') $c.holdSha2
        "host: $r1; daemon: $r2"
    }

    Invoke-Scenario $Iter 11 'cfapi-host restart' {
        $before = Get-TreeSnapshot $script:A
        $off = Get-LogLength 'host'
        Stop-Component 'host'
        Start-Sleep 1
        Start-CfapiHost
        Assert-That ((Get-TreeSnapshot $script:A) -eq $before) 'the placeholder tree changed across a host restart'
        $got = Get-Sha256 (Join-Path $A 'restart.bin')
        Assert-That ($got -eq $c.restSha) 'restart.bin read after the host restart differs'
        Test-Bidirectional 'h' $tok $A $B $Tmo
    }

    Invoke-Scenario $Iter 12 'daemon restart' {
        $before = Get-TreeSnapshot $script:A
        $hostOff = Get-LogLength 'host'
        Stop-Component 'daemonA'
        Start-Sleep 1
        $null = Start-Component 'daemonA' 'a' $script:Daemon
        Assert-That ($null -ne (Wait-Until { (Invoke-Cli 'a' @('status')) -notmatch 'not running|could not connect|refused' } 60)) 'daemon A did not come back'
        Wait-ProviderReady
        Assert-That (Wait-LogLine 'host' 'showing \d+ item\(s\)' 60 $hostOff) 'the host did not show the namespace again after the daemon came back'
        $syncWait = Wait-SyncReady
        Assert-That ((Get-TreeSnapshot $script:A) -eq $before) 'the placeholder tree changed across a daemon restart'
        Assert-That ((Get-Sha256 (Join-Path $A 'restart.bin')) -eq $c.restSha) 'restart.bin differs after the daemon restart'
        $bidi = Test-Bidirectional 'd' $tok $A $B $Tmo
        "sync ready ${syncWait}s after the start; $bidi"
    }

    Invoke-Scenario $Iter 15 'local edit during hydration' {
        $p = Join-Path $A 'race1.bin'
        Assert-That (Test-Placeholder $p) 'race1.bin is not an unread placeholder'
        $r = Start-BackgroundRead $p
        Assert-That $r.Active 'the hydration had already finished before the edit could be made; raise -RaceMB'
        $patch = New-Object byte[] 4096; (New-Object Random ($Iter * 17)).NextBytes($patch)
        $fs = [IO.File]::Open($p, 'Open', 'ReadWrite', 'ReadWrite,Delete')
        try { $null = $fs.Seek(1000000, 'Begin'); $fs.Write($patch, 0, $patch.Length) } finally { $fs.Dispose() }
        $outcome = Wait-BackgroundRead $r 120
        Assert-That ($outcome -ne 'hung') 'the reader hung after a local write to the file it was hydrating'
        $patchHash = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($patch)) -replace '-', '').ToLowerInvariant()
        Assert-That ((Get-RangeHash $p 1000000 4096) -eq $patchHash) 'the local write is not in the file'
        Assert-That ((Get-RangeHash $p 0 1000000) -eq $c.race1Head) 'the bytes before the edit differ from the remote ones'
        Assert-That ((Get-RangeHash $p 1004096 ($script:RaceBytes - 1004096)) -eq $c.race1Tail) 'the bytes after the edit differ from the remote ones'
        $aHash = Get-Sha256 $p
        $t = Wait-Until { (Get-Sha256 (Join-Path $B 'race1.bin')) -eq $aHash } $Tmo
        Assert-That ($null -ne $t) 'the edit made during the hydration never reached B'
        "edit kept and shared in ${t}s; interrupted read: $outcome"
    }

    Invoke-Scenario $Iter 16 'remote change during hydration' {
        $p = Join-Path $A 'race2.bin'
        Assert-That (Test-Placeholder $p) 'race2.bin is not an unread placeholder'
        $r = Start-BackgroundRead $p
        Assert-That $r.Active 'the hydration had already finished before the change could be made; raise -RaceMB'
        Update-FileRange $c.race2 3000000 4096 ($Iter * 19)
        $newSha = Get-Sha256 $c.race2
        $outcome = Wait-BackgroundRead $r 120
        Assert-That ($outcome -ne 'hung') 'the reader hung after the file changed on the other device'
        if ($outcome -match '^OK (\S+)') {
            Assert-That (($Matches[1] -eq $c.race2Sha) -or ($Matches[1] -eq $newSha)) "the read returned bytes that are neither version: $outcome"
        }
        $t = Wait-Until { (Get-Sha256 $p) -eq $newSha } $Tmo
        Assert-That ($null -ne $t) 'A never read the new version after the change made during its hydration'
        "settled on the new version in ${t}s; interrupted read: $($outcome.Substring(0, [math]::Min(50, $outcome.Length)))"
    }

    if ($OnDemandObserver -ne '') {
        Invoke-Scenario $Iter 17 'on-demand external observer (allocated bytes)' {
            $outFile = Join-Path $script:WorkDir ("observer-it{0:D2}.json" -f $Iter)
            $observerArgs = @($OnDemandObserver, '--cli', $script:Cli, '--a-root', (Join-Path $script:A "observer-$Iter"), '--b-root', (Join-Path $script:B "observer-$Iter"),
                '--block-store', (Join-Path $script:WorkDir 'cfga\blocks'), '--out', $outFile)
            if (-not $ObserverFullCorpus) { $observerArgs += '--small' }
            # A read of an unread placeholder is refused until the peer session is up (see Wait-SyncReady).
            $null = Wait-SyncReady
            Set-DeviceEnv 'a'
            $o = & python @observerArgs 2>&1 | Out-String
            Assert-That (Test-Path $outFile) "the observer wrote no result: $o"
            $r = Get-Content -Raw $outFile | ConvertFrom-Json
            Assert-That ($r.final_state -in 'VALID', 'SMOKE') "the observer measurement was $($r.final_state): $(($r.PSObject.Properties | Where-Object Name -in 'refused', 'not_applicable', 'detail' | ForEach-Object Value) -join ' ')"
            $d = $r.metrics.deltas
            Assert-That ($r.metrics.reopen_success) 'a re-open after the eviction did not return the right bytes'
            Assert-That ($d.hydrate_working_tree_bytes -gt 0) 'hydration allocated no bytes in the folder'
            Assert-That ($d.working_tree_released_by_evict_bytes -gt 0) 'the evict released no bytes of the folder'
            "hydrate +$($d.hydrate_working_tree_bytes) B in the folder, evict released $($d.working_tree_released_by_evict_bytes) B of the folder and $($d.block_store_released_by_evict_bytes) B of the block store; result in $outFile"
        }
    }

    if (-not $SkipReboot) { Start-RebootScenario $Iter $tok }
    else { Finish-Iteration $Iter }
}

# Writes a file on each side and requires it to appear on the other, plus a placeholder read.
function Test-Bidirectional([string]$Tag, [string]$Tok, [string]$A, [string]$B, [int]$Tmo) {
    [IO.File]::WriteAllText((Join-Path $B "bidi-$Tag-b.txt"), "from B $Tag $Tok", (New-Object Text.UTF8Encoding($false)))
    $t1 = Wait-Until { (Test-Path -LiteralPath (Join-Path $A "bidi-$Tag-b.txt")) -and ((Get-TextNoBom (Join-Path $A "bidi-$Tag-b.txt")) -ceq "from B $Tag $Tok") } $Tmo
    Assert-That ($null -ne $t1) 'a file created on B did not reach A after the restart'
    [IO.File]::WriteAllText((Join-Path $A "bidi-$Tag-a.txt"), "from A $Tag $Tok", (New-Object Text.UTF8Encoding($false)))
    $t2 = Wait-RemoteText (Join-Path $B "bidi-$Tag-a.txt") "from A $Tag $Tok" $Tmo
    Assert-That ($null -ne $t2) 'a file created on A did not reach B after the restart'
    return "B to A ${t1}s, A to B ${t2}s"
}

# Starts a separate process that reads the file front to back; see Wait-BackgroundRead. `Active` tells whether the read
# was still going (neither finished nor failed) when this returned, i.e. whether a change made now lands during it.
function Start-BackgroundRead([string]$Path) {
    $prog = Join-Path $script:WorkDir 'read.progress'; $res = Join-Path $script:WorkDir 'read.result'
    Remove-Item $prog, $res -ErrorAction SilentlyContinue
    $q = { param($x) '"' + $x + '"' }
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (& $q (Join-Path $PSScriptRoot 'read-file.ps1')), (& $q $Path), (& $q $prog), (& $q $res))
    $p = Start-Process powershell.exe -ArgumentList $argList -WindowStyle Hidden -PassThru
    # Give the reader time to open the file and block in the hydration, or to start delivering bytes.
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path $prog) -and -not (Test-Path $res) -and $sw.Elapsed.TotalSeconds -lt 1.5) { Start-Sleep -Milliseconds 40 }
    return [pscustomobject]@{ Process = $p; Progress = $prog; Result = $res; Active = -not (Test-Path $res) }
}

# The reader's outcome: "OK <sha256> <bytes>", "ERR <message>", or "hung" when it is still going after $TimeoutSec.
function Wait-BackgroundRead($Reader, [int]$TimeoutSec) {
    $end = Wait-Until { Test-Path $Reader.Result } $TimeoutSec
    if ($null -eq $end) { Stop-Process -Id $Reader.Process.Id -Force -ErrorAction SilentlyContinue; return 'hung' }
    return (Read-SharedText $Reader.Result).Trim()
}

# Starts a background read of a placeholder, restarts $Key as soon as bytes are flowing, and requires: no hang, no
# wrong bytes, a correct read afterwards.
function Test-RestartDuringRead([string]$Key, [string]$Path, [string]$ExpectSha) {
    Assert-That (Test-Placeholder $Path) "$Path is not an unread placeholder"
    $reader = Start-BackgroundRead $Path
    $prog = $reader.Progress; $res = $reader.Result
    $bytes = if (Test-Path $prog) { (Read-SharedText $prog).Trim() } else { '0' }
    $hostOff = Get-LogLength 'host'
    Stop-Component $Key
    $landed = -not (Test-Path $res)
    Start-Sleep 1
    if ($Key -eq 'host') { Start-CfapiHost } else {
        $null = Start-Component 'daemonA' 'a' $script:Daemon
        Assert-That ($null -ne (Wait-Until { (Invoke-Cli 'a' @('status')) -notmatch 'not running|could not connect|refused' } 60)) 'daemon A did not come back'
        Wait-ProviderReady
        Assert-That (Wait-LogLine 'host' 'showing \d+ item\(s\)' 60 $hostOff) 'the host did not re-attach'
    }
    $end = Wait-Until { Test-Path $res } 120
    if ($null -eq $end) {
        Stop-Process -Id $reader.Process.Id -Force -ErrorAction SilentlyContinue
        throw "the reader hung for 120 s after the $Key came back (bytes read when stopped: $bytes)"
    }
    $r = (Read-SharedText $res).Trim()
    if ($r.StartsWith('OK')) {
        $sha = ($r -split ' ')[1]
        Assert-That ($sha -eq $ExpectSha) "the interrupted read ended OK with the wrong bytes ($r)"
    }
    $again = Wait-Until { (Test-Path -LiteralPath $Path) -and ((Get-Sha256 $Path) -eq $ExpectSha) } 120
    Assert-That ($null -ne $again) "a fresh read after the $Key restart did not return the right bytes"
    if ($Key -ne 'host') { $null = Wait-SyncReady }
    Assert-That ($landed) "the restart did not land in flight (the read had finished: $r); raise -HoldMB"
    $outcome = if ($r.StartsWith('OK')) { 'read survived' } else { 'read failed cleanly (' + ($r -replace '\s+', ' ').Substring(0, [math]::Min(60, $r.Length)) + ')' }
    return "killed at $bytes bytes, $outcome, fresh read ok in ${again}s"
}

# ---- reboot ----------------------------------------------------------------------------------------------------

function Start-RebootScenario([int]$Iter, [string]$Tok) {
    $c = $script:Ctx; $A = $script:ItA; $B = $script:ItB; $Tmo = $script:Timeout
    $script:PendingOk = $false
    if (-not (Test-Path $RebootMarker)) {
        if (-not $script:RebootSkipped) { Write-Host "   scenario 13 (reboot) not run: $RebootMarker does not exist (it declares the machine dedicated to these runs)"; $script:RebootSkipped = $true }
        Finish-Iteration $Iter
        return
    }
    Invoke-Scenario $Iter 13 'Windows reboot (before)' {
        $b1 = New-Seed 'reboot-b1.bin' 'rand' 3400003 ($Iter * 100 + 9)
        $b2 = New-Seed 'reboot-b2.bin' 'rand' 3500009 ($Iter * 100 + 10)
        $sha1 = Get-Sha256 $b1; $sha2 = Get-Sha256 $b2
        Assert-That ($null -ne (Wait-Until { (Test-Path -LiteralPath (Join-Path $A 'reboot-b2.bin')) -and (Test-Path -LiteralPath (Join-Path $A 'reboot-b1.bin')) } $Tmo)) 'reboot files did not appear on A'
        Assert-That ((Get-Sha256 (Join-Path $A 'reboot-b1.bin')) -eq $sha1) 'reboot-b1.bin differs before the reboot'
        [IO.File]::WriteAllText((Join-Path $A 'reboot-a.txt'), "A before reboot $Tok", (New-Object Text.UTF8Encoding($false)))
        Assert-That ($null -ne (Wait-RemoteText (Join-Path $B 'reboot-a.txt') "A before reboot $Tok" $Tmo)) 'reboot-a.txt did not reach B before the reboot'
        Assert-That ($null -ne (Wait-Until { Test-NamespaceConverged } $Tmo)) 'the two sides were not converged before the reboot'
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')
        $script:State.pending = [pscustomobject]@{ iteration = $Iter; tok = $Tok; boot = $boot; sha1 = $sha1; sha2 = $sha2; snapshot = (Get-TreeSnapshot $script:A) }
        Save-State
        'armed'
    } -RecordOnlyFailure
    if ($script:State.pending) {
        Write-Host '== rebooting the machine (exit 75: run the same command again when it is back)'
        Stop-AllComponents
        & shutdown.exe /r /t 5 /f /c 'cfapi e2e reboot scenario'
        Start-Sleep 60
        exit 75
    }
    Finish-Iteration $Iter
}

function Complete-Reboot {
    $p = $script:State.pending
    $Iter = [int]$p.iteration
    $script:It = 'it{0:D2}' -f $Iter
    $script:ItA = Join-Path $script:A $script:It; $script:ItB = Join-Path $script:B $script:It
    $A = $script:ItA; $B = $script:ItB; $Tmo = $script:Timeout
    Invoke-Scenario $Iter 13 'Windows reboot' {
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')
        Assert-That ($boot -ne $p.boot) 'the machine did not actually reboot'
        $syncWait = Wait-SyncReady
        Assert-That ((Get-TreeSnapshot $script:A) -eq $p.snapshot) 'the placeholder tree differs after the reboot'
        Assert-That ((Get-Sha256 (Join-Path $A 'reboot-b1.bin')) -eq $p.sha1) 'the hydrated file differs after the reboot'
        Assert-That ((Get-Sha256 (Join-Path $A 'reboot-b2.bin')) -eq $p.sha2) 'the placeholder read after the reboot differs'
        Assert-That ((Get-TextNoBom (Join-Path $A 'reboot-a.txt')) -ceq "A before reboot $($p.tok)") 'reboot-a.txt differs after the reboot'
        $r = Test-Bidirectional 'r' $p.tok $A $B $Tmo
        "tree, hydrated and placeholder reads survived (sync ready ${syncWait}s after the start); $r"
    }
    $script:State.pending = $null
    Save-State
    Finish-Iteration $Iter
}

function Finish-Iteration([int]$Iter) {
    # Remove the iteration's files on B and see the deletion arrive on A (a remote delete of hydrated and unread files).
    if ($Only.Count -eq 0) {
        $dirA = $script:ItA; $dirB = $script:ItB
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $ok = $true; $detail = ''
        try {
            Remove-Item -LiteralPath $dirB -Recurse -Force
            $t = Wait-Until { -not (Test-Path -LiteralPath $dirA) } $script:Timeout
            Assert-That ($null -ne $t) 'the remote delete of the iteration directory did not reach A'
            $detail = "removed on A after ${t}s"
        } catch { $ok = $false; $detail = $_.Exception.Message }
        Add-Result $Iter 14 'remote delete (cleanup)' $ok $sw.Elapsed.TotalSeconds $detail
        if (-not $ok) { Save-FailureLogs $Iter 14 }
    }
    $script:State.next_iteration = $Iter + 1
    Save-State
}

# ---- main ------------------------------------------------------------------------------------------------------

try {
    if ($Fresh -or -not (Test-Path $script:StatePath)) { Initialize-Run }
    else {
        $script:State = Get-Content $script:StatePath -Raw | ConvertFrom-Json
        $script:State.results = @($script:State.results)
        $script:A = Join-Path (Join-Path (Join-Path $script:WorkDir 'profile-a') 'YadoriLink') $script:State.display
        Resume-Run
    }
} catch {
    Write-Host "SETUP FAILED: $($_.Exception.Message)"
    Save-FailureLogs 0 0
    Stop-AllComponents
    exit 2
}

if ($script:State.pending) { Complete-Reboot }
while ($script:State.next_iteration -le $Iterations) { Invoke-Iteration ([int]$script:State.next_iteration) }

Write-Host ''
Write-Host '== summary (passes / runs per scenario)'
$script:State.results | Group-Object scenario | Sort-Object { [int]$_.Name } | ForEach-Object {
    $pass = @($_.Group | Where-Object ok).Count
    '{0,3}  {1,-36} {2,3}/{3,-3}' -f $_.Name, $_.Group[0].name, $pass, $_.Count
} | Write-Host
if ($script:RebootSkipped) { Write-Host '  13  Windows reboot: not run (no machine marker)' }
$bad = @($script:State.results | Where-Object { -not $_.ok })
foreach ($b in $bad) { Write-Host ("FAILED it{0:D2} S{1:D2} {2}: {3}" -f $b.iteration, $b.scenario, $b.name, $b.detail) }
Stop-AllComponents
if ($bad.Count -gt 0) { exit 1 }
exit 0
