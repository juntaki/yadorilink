# Builds the Windows installer and enforces the SEC-LOCAL-3 release policy:
# release builds must be Authenticode-signed through an Inno Setup SignTool
# profile. Every build, signed or unsigned, gets a SHA-256 sidecar — every
# downloadable release artifact must have a published checksum regardless
# of signing status (a signed
# installer can still be checksummed to detect corruption/tampering in
# transit independent of the Authenticode signature).
param(
    [string]$IsccPath = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    [string]$BinDir = "",
    [string]$ShellExtDir = "",
    [string]$SignToolName = "",
    [switch]$Release
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$issPath = Join-Path $scriptDir "yadorilink.iss"
$outputPath = Join-Path $scriptDir "Output\yadorilink-setup.exe"

if (-not (Test-Path -LiteralPath $IsccPath)) {
    throw "ISCC.exe not found at $IsccPath"
}

if ($Release -and [string]::IsNullOrWhiteSpace($SignToolName)) {
    throw "Release builds must pass -SignToolName so yadorilink-setup.exe is Authenticode-signed."
}

$args = @()
if (-not [string]::IsNullOrWhiteSpace($SignToolName)) {
    $args += "/DYadoriLinkSignTool=$SignToolName"
}
if (-not [string]::IsNullOrWhiteSpace($BinDir)) {
    $args += "/DBinDir=$BinDir"
}
if (-not [string]::IsNullOrWhiteSpace($ShellExtDir)) {
    $args += "/DShellExtDir=$ShellExtDir"
}
$args += $issPath

& $IsccPath @args
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if (-not (Test-Path -LiteralPath $outputPath)) {
    throw "Expected installer was not produced: $outputPath"
}

if (-not [string]::IsNullOrWhiteSpace($SignToolName)) {
    $signature = Get-AuthenticodeSignature -LiteralPath $outputPath
    if ($signature.Status -ne "Valid") {
        throw "Installer signature is not valid: $($signature.Status)"
    }
    Write-Output "Verified Authenticode signature on $outputPath"
}

# Always write a checksum sidecar, signed or not (every downloadable
# release artifact SHALL have a published checksum).
$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath
$sidecar = "$outputPath.sha256"
"$($hash.Hash.ToLowerInvariant())  $(Split-Path -Leaf $outputPath)" | Set-Content -LiteralPath $sidecar -NoNewline
Write-Output "Wrote $sidecar"
