<#
.SYNOPSIS
    Resolves the folder that holds the file access index.
.DESCRIPTION
    Returns -IndexPath if given, else FileAccessIndexPath from the WyattTools config, else
    %LOCALAPPDATA%\WyattTools\FileAccessIndex. Missing or blank config keys fall through to the
    default, so older config.psd1 files keep working. Used by Update-FileAccessIndex and
    Get-FileAccess so both always agree on the location.
.PARAMETER IndexPath
    Explicit index folder. Blank or omitted means use config, then the default.
.EXAMPLE
    Get-FileAccessIndexPath
.NOTES
    Name: Get-FileAccessIndexPath
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-19
    Prerequisites: None
#>
function Get-FileAccessIndexPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [string]$IndexPath
    )

    if ($IndexPath) { return $IndexPath }

    $config = Get-WyattConfig
    if ($config -and $config.ContainsKey('FileAccessIndexPath') -and $config.FileAccessIndexPath) {
        return [string]$config.FileAccessIndexPath
    }
    return (Join-Path $env:LOCALAPPDATA 'WyattTools\FileAccessIndex')
}
