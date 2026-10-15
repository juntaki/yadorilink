# Copies every shipped PE file (shipped-binaries.txt) into one staging
# directory and, when -SignCommand is given, Authenticode-signs each staged
# copy before anything is packed. build-installer.ps1 then points Inno Setup
# and the binary archive at the staging directory, so the installer and the
# archive carry signed bytes only.
#
# -SignCommand is the one swappable signing step: a command line in which
# `$f` stands for the file to sign (the same convention as Inno Setup's
# /S option), e.g. a signtool PFX/thumbprint command today, a cloud HSM
# client later. No secret value lives in this repository; the caller builds
# the command from its own secrets.
#
# With -SignCommand every staged PE must verify as Valid afterwards, or this
# script fails. Without it the files are staged unchanged (unsigned builds).
param(
    [Parameter(Mandatory = $true)][string]$BinDir,
    [Parameter(Mandatory = $true)][string]$ShellExtDir,
    [Parameter(Mandatory = $true)][string]$StageDir,
    [string]$SignCommand = ""
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "shipped-binaries.ps1")

$sources = @{ bin = $BinDir; shell = $ShellExtDir }
if (Test-Path -LiteralPath $StageDir) { Remove-Item -LiteralPath $StageDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

foreach ($entry in Get-ShippedBinaries) {
    $src = Join-Path $sources[$entry.Source] $entry.Name
    if (-not (Test-Path -LiteralPath $src)) { throw "shipped binary missing: $src" }
    $dst = Join-Path $StageDir $entry.Name
    Copy-Item -LiteralPath $src -Destination $dst
    if (-not [string]::IsNullOrWhiteSpace($SignCommand)) {
        $full = (Resolve-Path -LiteralPath $dst).Path
        $line = $SignCommand.Replace('$f', '"' + $full + '"')
        & cmd.exe /d /s /c "`"$line`""
        if ($LASTEXITCODE -ne 0) { throw "signing failed ($LASTEXITCODE) for $($entry.Name)" }
        $sig = Get-AuthenticodeSignature -LiteralPath $full
        if ($sig.Status -ne "Valid") { throw "$($entry.Name) is not validly signed after signing: $($sig.Status)" }
        Write-Output "signed $($entry.Name)"
    }
}
