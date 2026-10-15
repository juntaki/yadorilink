# Reads shipped-binaries.txt (the single list of shipped PE files).
$script:ShippedListPath = Join-Path $PSScriptRoot "shipped-binaries.txt"
function Get-ShippedBinaries {
    Get-Content -LiteralPath $script:ShippedListPath |
        Where-Object { $_.Trim() -ne "" -and -not $_.TrimStart().StartsWith("#") } |
        ForEach-Object {
            $p = $_.Trim() -split '\s+'
            [pscustomobject]@{ Source = $p[0]; Name = $p[1] }
        }
}
