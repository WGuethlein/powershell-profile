<#
.SYNOPSIS
    Pulls a branch from origin.
.DESCRIPTION
    Git shorthand wrapper: Pulls a branch from origin.
.PARAMETER Branch
    Branch name to pull.
.EXAMPLE
    pull main
.NOTES
    Name: pull
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: git on PATH
#>
function pull {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Branch
    )
    git pull origin $Branch
}
