<#
.SYNOPSIS
    Loads the WyattTools configuration hashtable.
.DESCRIPTION
    Reads WyattTools\config.psd1 (real values, gitignored). If it is missing, falls back to
    config.example.psd1 and warns once. The result is cached in module scope.
.EXAMPLE
    (Get-WyattConfig).AADConnectServer
.NOTES
    Name: Get-WyattConfig
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None
#>
function Get-WyattConfig {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    if ($script:WyattConfig) { return $script:WyattConfig }

    $realPath    = Join-Path $script:WyattModuleRoot 'config.psd1'
    $examplePath = Join-Path $script:WyattModuleRoot 'config.example.psd1'

    if (Test-Path -LiteralPath $realPath) {
        $script:WyattConfig = Import-PowerShellDataFile -Path $realPath
    }
    else {
        Write-Warning "WyattTools: config.psd1 not found; using placeholder values from config.example.psd1. Copy it to config.psd1 and edit."
        $script:WyattConfig = Import-PowerShellDataFile -Path $examplePath
    }
    return $script:WyattConfig
}
