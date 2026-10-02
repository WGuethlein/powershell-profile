<#
.SYNOPSIS
    Stages changes (default: everything under the current directory).
.DESCRIPTION
    Git shorthand wrapper: Stages changes (default: everything under the current directory).
.PARAMETER Path
    Path to stage. Default ".".
.EXAMPLE
    add .\file.txt
.NOTES
    Name: add
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: git on PATH
#>
function add {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$Path = "."
    )
    git add $Path
}
