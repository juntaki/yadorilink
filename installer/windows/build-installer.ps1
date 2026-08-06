# Builds the Windows installer and enforces the SEC-LOCAL-3 release policy:
# release builds must be Authenticode-signed through an Inno Setup SignTool
# profile. Every build, signed or unsigned, gets a SHA-256 sidecar -- every
# downloadable release artifact must have a published checksum regardless
# of signing status (a signed
# installer can still be checksummed to detect corruption/tampering in
# transit independent of the Authenticode signature).
param(
    [string]$IsccPath = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    [string]$BinDir = "",
    [string]$ShellExtDir = "",
    [string]$SignToolName = "",
    [string]$SignToolCommand = "",
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
if ($Release -and [string]::IsNullOrWhiteSpace($SignToolCommand)) {
    throw "Release builds must pass -SignToolCommand so Inno Setup can invoke the signing tool."
}
if ($Release -and (
    [string]::IsNullOrWhiteSpace($env:YADORILINK_RELEASE_MANIFEST_KEY_ID) -or
    [string]::IsNullOrWhiteSpace($env:YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX)
)) {
    throw "Release builds require YADORILINK_RELEASE_MANIFEST_KEY_ID and YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX."
}
if ($Release) {
    $manifestPublicKey = $env:YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX.Trim()
    if ($manifestPublicKey -notmatch '^[0-9a-fA-F]{64}$') {
        throw "YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX must be exactly 64 hexadecimal characters."
    }
    if ($manifestPublicKey.ToLowerInvariant() -eq '00e033f866c263139ff4afd165e75bae3cfca67eb32399dddd6e33a3251af1e3') {
        throw "Refusing release build with the known development manifest public key."
    }
}

# A release installer must contain a daemon whose startup path enforces the
# update trust-root tripwire. Building the workspace here prevents callers
# from accidentally packaging a previously-built ordinary binary that lacks
# the feature. Local/unsigned installer builds keep accepting prebuilt output.
if ($Release) {
    Push-Location $repoRoot
    try {
        & cargo build --workspace --release --features "yadorilink-daemon/enforce-release-trust-root"
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }
    finally {
        Pop-Location
    }
    if ([string]::IsNullOrWhiteSpace($BinDir)) {
        $BinDir = Join-Path $repoRoot "target\release"
    }
}

$args = @()
if (-not [string]::IsNullOrWhiteSpace($SignToolName)) {
    if ([string]::IsNullOrWhiteSpace($SignToolCommand)) {
        throw "-SignToolCommand is required when -SignToolName is set."
    }
    $args += "/S$SignToolName=$SignToolCommand"
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
