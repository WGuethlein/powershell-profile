<#
.SYNOPSIS
    Commits staged changes with a message.
.DESCRIPTION
    Git shorthand wrapper: Commits staged changes with a message.
.PARAMETER Message
    Commit message.
.EXAMPLE
    commit "Fix typo"
.NOTES
    Name: commit
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: git on PATH
#>
function commit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message
    )
    git commit -m $Message
}
