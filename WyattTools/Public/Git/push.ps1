<#
.SYNOPSIS
    Pushes a branch to origin.
.DESCRIPTION
    Git shorthand wrapper: Pushes a branch to origin.
.PARAMETER Branch
    Branch name to push.
.EXAMPLE
    push main
.NOTES
    Name: push
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: git on PATH
#>
function push {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Branch
    )
    git push origin $Branch
}
