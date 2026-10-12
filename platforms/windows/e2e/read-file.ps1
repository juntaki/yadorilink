# Reads one file front to back through the ordinary file API and reports how that went. Started by run-e2e.ps1 as a
# separate process so that a restart of the daemon or of the Cloud Files host can be injected while the read is in
# flight. Writes the number of bytes read so far to <Progress> and, when it ends, "OK <sha256> <bytes>" or
# "ERR <message>" to <Result>.
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Progress,
    [Parameter(Mandatory = $true)][string]$Result
)
$ErrorActionPreference = 'Stop'
try {
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite,Delete')
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        $buf = New-Object byte[] (256KB)
        $total = 0L
        while ($true) {
            $n = $fs.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $null = $sha.TransformBlock($buf, 0, $n, $null, 0)
            $total += $n
            [IO.File]::WriteAllText($Progress, "$total")
        }
        $null = $sha.TransformFinalBlock($buf, 0, 0)
        $hex = ([BitConverter]::ToString($sha.Hash) -replace '-', '').ToLowerInvariant()
        [IO.File]::WriteAllText($Result, "OK $hex $total")
    } finally { $fs.Dispose() }
} catch {
    [IO.File]::WriteAllText($Result, "ERR $($_.Exception.Message)")
}
