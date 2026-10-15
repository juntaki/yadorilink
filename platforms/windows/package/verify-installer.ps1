# platforms/windows/package/verify-installer.ps1
#
# Standalone verification for a built (or downloaded) yadorilink-setup.exe.
# Unlike the signature check already inline in build-installer.ps1 (which only runs
# right after that same script produces the artifact, and only for
# -SignToolName builds), this can be pointed at any yadorilink-setup.exe --
# e.g. one downloaded from a release page -- to independently confirm its
# checksum and Authenticode signature before anyone runs it.
#
# Checks performed:
#  1. SHA-256 checksum against the artifact's <name>.sha256 sidecar
#  (release-blocking: every artifact must have a published checksum).
#  2. Get-AuthenticodeSignature -- reports signed/unsigned status.
#
# By default this only *reports* signature status without failing on
# unsigned (matching this project's documented allowance for local/interim
# unsigned builds -- see platforms/windows/package/README.md's "Signing and
# checksums" section). Pass
# -Release to additionally require a valid Authenticode signature, per
# the release rule that shipped installers must be signed and checksummed.
#
# Note on Microsoft Store metadata: this repo does not currently produce
# an MSIX/Store package (only the Inno Setup.exe installer built here),
# so there is no Store metadata to verify yet. Add a Store metadata check
# here if/when this project starts publishing to the Microsoft Store.
#
# Usage:
#  powershell -File platforms\windows\package\verify-installer.ps1 -Path.\yadorilink-setup.exe
#  powershell -File platforms\windows\package\verify-installer.ps1 -Path.\yadorilink-setup.exe -Release
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [switch]$Release,
    # A staged payload directory, an unpacked binary archive or an installed
    # layout (%ProgramFiles%\yadorilink). Every shipped PE file listed in
    # shipped-binaries.txt must be present there; with -Release each must also
    # carry a valid Authenticode signature (a missing file or signature fails).
    # An installed layout's _stage\target\release copies are checked too.
    [string]$PayloadDir = ""
)

$ErrorActionPreference = "Stop"
$failures = 0

function Write-Ok([string]$msg) { Write-Output "OK: $msg" }
function Write-Fail([string]$msg) {
    Write-Output "FAIL: $msg"
    $script:failures++
}
function Write-Note([string]$msg) { Write-Output "NOTE: $msg" }

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Error "artifact not found: $Path"
    exit 2
}

$resolvedPath = (Resolve-Path -LiteralPath $Path).Path

Write-Output "== checksum =="
$sidecar = "$resolvedPath.sha256"
if (Test-Path -LiteralPath $sidecar) {
    $expected = (Get-Content -LiteralPath $sidecar).Split()[0].Trim().ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedPath).Hash.ToLowerInvariant()
    if ($actual -eq $expected) {
        Write-Ok "checksum matches $sidecar"
    } else {
        Write-Fail "checksum mismatch against $sidecar (expected $expected, got $actual)"
    }
} else {
    Write-Fail "no checksum sidecar found at $sidecar"
}

Write-Output "== Get-AuthenticodeSignature =="
$signature = Get-AuthenticodeSignature -LiteralPath $resolvedPath
Write-Output "Status: $($signature.Status); StatusMessage: $($signature.StatusMessage)"
if ($signature.Status -eq "Valid") {
    Write-Ok "Authenticode signature is valid (signer: $($signature.SignerCertificate.Subject))"
} elseif ($Release) {
    Write-Fail "Authenticode signature is not valid: $($signature.Status) (-Release requires a valid signature)"
} else {
    Write-Note "unsigned/invalid signature ($($signature.Status)) -- expected for local/interim builds; use -Release to enforce signing"
}

foreach ($dir in @($PayloadDir | Where-Object { $_ })) {
    Write-Output "== shipped PE files in $dir =="
    . (Join-Path $PSScriptRoot "shipped-binaries.ps1")
    $dirs = @($dir)
    $stage = Join-Path $dir "_stage\target\release"
    if (Test-Path -LiteralPath $stage) { $dirs += $stage }
    foreach ($d in $dirs) {
        foreach ($entry in Get-ShippedBinaries) {
            $file = Join-Path $d $entry.Name
            # _stage\target\release holds only the two shell-extension files.
            if ($d -eq $stage -and $entry.Source -ne "shell") { continue }
            if (-not (Test-Path -LiteralPath $file)) { Write-Fail "shipped file missing: $file"; continue }
            $sig = Get-AuthenticodeSignature -LiteralPath $file
            if ($sig.Status -eq "Valid") {
                Write-Ok "$file signed ($($sig.SignerCertificate.Subject))"
            } elseif ($Release) {
                Write-Fail "$file is not validly signed: $($sig.Status)"
            } else {
                Write-Note "$file signature status $($sig.Status) -- use -Release to enforce signing"
            }
        }
    }
}

Write-Output "== Microsoft Store metadata =="
Write-Note "no MSIX/Store package produced by this repo yet; Store metadata verification is not applicable"

# Best-effort, non-blocking check for the
# status app's Scheduled Task registration (status-app-task.ps1). This is
# NOT a check of $Path itself (an Inno Setup.exe is a self-extracting
# archive this script has no unpacker for, unlike platforms/macos/package/
# verify-pkg.sh's `pkgutil --expand-full` on a real.pkg) -- it only means
# something when run on a machine where yadorilink-setup.exe was actually
# executed, e.g. right after a real install in CI or by hand on a Windows
# VM. Never fails verification on its own (even under -Release) since a
# fresh checkout's verify-installer.ps1 run has nothing installed yet.
Write-Output "== YadoriLinkStatusApp scheduled task (best-effort, post-install only) =="
$statusAppTask = Get-ScheduledTask -TaskName "YadoriLinkStatusApp" -ErrorAction SilentlyContinue
if ($statusAppTask) {
    Write-Ok "YadoriLinkStatusApp scheduled task is registered (state: $($statusAppTask.State))"
} else {
    Write-Note "YadoriLinkStatusApp scheduled task not found on this machine -- expected unless yadorilink-setup.exe was just run here"
}

Write-Output ""
if ($failures -gt 0) {
    Write-Error "verify-installer.ps1: $failures check(s) failed for $resolvedPath"
    exit 1
}
Write-Output "verify-installer.ps1: all required checks passed for $resolvedPath"
exit 0
