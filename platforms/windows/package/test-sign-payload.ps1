# Proves the staging, signing and verification path with a throw-away
# self-signed certificate (no real signing identity involved). Run
# on a disposable Windows host: the test certificate is trusted in
# LocalMachine\Root only while the test runs and is removed afterwards.
#
#   powershell -ExecutionPolicy Bypass -File platforms\windows\package\test-sign-payload.ps1
$ErrorActionPreference = "Stop"
$pkg = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $pkg "shipped-binaries.ps1")
$work = Join-Path $env:TEMP ("sign-payload-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path "$work\bin", "$work\shell" | Out-Null
$cert = $null
$rootCopy = $null
$failed = 0
function Check([string]$name, [bool]$ok) {
    if ($ok) { Write-Output "PASS: $name" } else { Write-Output "FAIL: $name"; $script:failed++ }
}
# System binaries are catalog-signed (they read as Valid without an embedded
# signature); a trailing byte changes the hash so the stand-in is truly unsigned.
function MakeUncatalogued([string]$path) {
    $fs = [IO.File]::Open($path, "Append"); $fs.WriteByte(0); $fs.Close()
}
function RunVerify([string]$dir, [switch]$Release) {
    $a = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $pkg "verify-installer.ps1"), "-Path", "$work\setup.exe", "-PayloadDir", $dir)
    if ($Release) { $a += "-Release" }
    & powershell.exe @a | Out-Null
    return $LASTEXITCODE
}
try {
    # Stand-in PE files: copies of real system binaries under the shipped names.
    foreach ($e in Get-ShippedBinaries) {
        $donor = "$env:SystemRoot\System32\whoami.exe"
        Copy-Item $donor (Join-Path "$work\$($e.Source)" $e.Name)
        MakeUncatalogued (Join-Path "$work\$($e.Source)" $e.Name)
    }
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=sign-payload-test" -CertStoreLocation Cert:\CurrentUser\My
    $rootCopy = "$work\test.cer"
    Export-Certificate -Cert $cert -FilePath $rootCopy | Out-Null
    Import-Certificate -FilePath $rootCopy -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

    $signer = "$work\signer.ps1"
    Set-Content $signer 'param([string]$File,[string]$Thumb) $c = Get-Item "Cert:\CurrentUser\My\$Thumb"; $r = Set-AuthenticodeSignature -LiteralPath $File -Certificate $c; if ($r.Status -ne "Valid") { exit 1 }'
    $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$signer`" -File `$f -Thumb $($cert.Thumbprint)"

    # Stand-in installer, signed like the real one (Inno SignTool signs it).
    Copy-Item "$env:SystemRoot\System32\whoami.exe" "$work\setup.exe"
    MakeUncatalogued "$work\setup.exe"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $signer -File "$work\setup.exe" -Thumb $cert.Thumbprint
    $h = (Get-FileHash -Algorithm SHA256 "$work\setup.exe").Hash.ToLowerInvariant()
    "$h  setup.exe" | Set-Content "$work\setup.exe.sha256" -NoNewline

    # unsigned staging: all files present, none signed, -Release verify fails
    & (Join-Path $pkg "sign-payload.ps1") -BinDir "$work\bin" -ShellExtDir "$work\shell" -StageDir "$work\unsigned"
    Check "unsigned staging copies every listed file" ((Get-ShippedBinaries | Where-Object { Test-Path "$work\unsigned\$($_.Name)" }).Count -eq (Get-ShippedBinaries).Count)
    Check "unsigned payload passes report-only verify" ((RunVerify "$work\unsigned") -eq 0)
    Check "unsigned payload fails -Release verify" ((RunVerify "$work\unsigned" -Release) -ne 0)

    # signed staging: every file Valid, -Release verify passes
    & (Join-Path $pkg "sign-payload.ps1") -BinDir "$work\bin" -ShellExtDir "$work\shell" -StageDir "$work\signed" -SignCommand $cmd
    $statuses = Get-ShippedBinaries | ForEach-Object { (Get-AuthenticodeSignature "$work\signed\$($_.Name)").Status }
    Check "every staged PE is Valid" (@($statuses | Where-Object { $_ -ne "Valid" }).Count -eq 0)
    Check "signed payload passes -Release verify" ((RunVerify "$work\signed" -Release) -eq 0)

    # one unsigned file among signed ones must fail
    $victim = (Get-ShippedBinaries | Select-Object -Last 1).Name
    Copy-Item "$work\unsigned\$victim" "$work\signed\$victim" -Force
    Check "one unsigned PE fails -Release verify" ((RunVerify "$work\signed" -Release) -ne 0)

    # a missing file must fail even in report-only mode
    Remove-Item "$work\signed\$victim"
    Check "missing PE fails verify" ((RunVerify "$work\signed") -ne 0)

    # a failing signing command must fail staging
    $threw = $false
    try { & (Join-Path $pkg "sign-payload.ps1") -BinDir "$work\bin" -ShellExtDir "$work\shell" -StageDir "$work\bad" -SignCommand "where.exe nosuchprogram-xyz `$f" } catch { $threw = $true }
    Check "failing sign command fails staging" $threw
}
finally {
    if ($cert) {
        Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $cert.Thumbprint } | Remove-Item
        Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
if ($failed -gt 0) { Write-Output "$failed check(s) failed"; exit 1 }
Write-Output "all checks passed"
