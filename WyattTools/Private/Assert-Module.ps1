<#
.SYNOPSIS
    Ensures a PowerShell module is available and imported.
.DESCRIPTION
    Throws a friendly error if the module is not installed; imports it if not already loaded.
.PARAMETER Name
    Module name, for example ActiveDirectory.
.EXAMPLE
    Assert-Module -Name ActiveDirectory
.NOTES
    Name: Assert-Module
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None
#>
function Assert-Module {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    if (Get-Module -Name $Name) { return }
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "Module '$Name' not found. Install it (for ActiveDirectory, install the RSAT tools)."
    }
    Import-Module -Name $Name -ErrorAction Stop
}
