<#
.SYNOPSIS
    Returns the default export directory.
.DESCRIPTION
    Uses ExportDirectory from the WyattTools config, or the current location when blank.
.EXAMPLE
    Get-ExportDirectory
.NOTES
    Name: Get-ExportDirectory
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None
#>
function Get-ExportDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $dir = (Get-WyattConfig).ExportDirectory
    if ([string]::IsNullOrWhiteSpace($dir)) { $dir = (Get-Location).Path }
    return $dir
}
