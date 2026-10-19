<#
.SYNOPSIS
    Loads the file access index (CSV files) written by Update-FileAccessIndex.
.DESCRIPTION
    Reads acl-index.csv, scan-errors.csv and scan-info.json from the index folder. The parsed
    result is cached in module scope and reused until acl-index.csv or scan-info.json changes
    (keyed by LastWriteTime). Throws a friendly error if the index has not been built yet.
.PARAMETER IndexPath
    Index folder (already resolved; see Get-FileAccessIndexPath).
.EXAMPLE
    $index = Import-FileAccessIndex -IndexPath (Get-FileAccessIndexPath)
.NOTES
    Name: Import-FileAccessIndex
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-19
    Prerequisites: None
#>
function Import-FileAccessIndex {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$IndexPath
    )

    $csvPath  = Join-Path $IndexPath 'acl-index.csv'
    $errPath  = Join-Path $IndexPath 'scan-errors.csv'
    $infoPath = Join-Path $IndexPath 'scan-info.json'

    if (-not (Test-Path -LiteralPath $csvPath -PathType Leaf)) {
        throw "No file access index found at '$IndexPath'. Run Update-FileAccessIndex first (it scans the file shares and writes the index)."
    }

    # Cache key: the index file's last write time (plus the info file, which changes with each scan).
    $stamp = (Get-Item -LiteralPath $csvPath).LastWriteTimeUtc.Ticks.ToString()
    if (Test-Path -LiteralPath $infoPath) { $stamp += '|' + (Get-Item -LiteralPath $infoPath).LastWriteTimeUtc.Ticks }

    if (-not $script:FileAccessIndexCache) { $script:FileAccessIndexCache = @{} }
    $cached = $script:FileAccessIndexCache[$csvPath]
    if ($cached -and $cached.Stamp -eq $stamp) { return $cached.Data }

    $rows   = @(Import-Csv -LiteralPath $csvPath -Encoding UTF8)
    $errors = @()
    if (Test-Path -LiteralPath $errPath) { $errors = @(Import-Csv -LiteralPath $errPath -Encoding UTF8) }
    $info = $null
    if (Test-Path -LiteralPath $infoPath) {
        try { $info = Get-Content -LiteralPath $infoPath -Raw -Encoding UTF8 | ConvertFrom-Json }
        catch { Write-Verbose "Could not read scan-info.json: $($_.Exception.Message)" }
    }

    # Scan time: scan-info.json if readable, else the CSV's write time.
    $scanTime = (Get-Item -LiteralPath $csvPath).LastWriteTime
    if ($info -and $info.ScanFinished) { $scanTime = [datetime]$info.ScanFinished }

    $data = [PSCustomObject]@{
        IndexPath = $IndexPath
        Rows      = $rows
        Errors    = $errors
        Info      = $info
        ScanTime  = $scanTime
        Roots     = @($rows | Where-Object { $_.IsRoot -eq 'True' } | ForEach-Object { $_.Root } | Sort-Object -Unique)
    }
    $script:FileAccessIndexCache[$csvPath] = @{ Stamp = $stamp; Data = $data }
    return $data
}
