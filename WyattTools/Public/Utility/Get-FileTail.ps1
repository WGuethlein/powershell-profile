<#
.SYNOPSIS
    Shows the last lines of a file, optionally following new content (like Linux tail).
.DESCRIPTION
    Displays the last N lines of a file (default 10). With -Follow, keeps watching the file for
    new content, like 'tail -f'.
.PARAMETER Path
    The file to tail.
.PARAMETER Lines
    Number of lines to show from the end of the file. Default 10. Alias: n.
.PARAMETER Follow
    Keep watching the file for new content. Alias: f.
.EXAMPLE
    tail app.log
.EXAMPLE
    tail -f app.log
.EXAMPLE
    tail -n 50 app.log
.EXAMPLE
    tail app.log 50 -f
.EXAMPLE
    tail -n 200 app.log | grep -i error
    Shows the last 200 lines and keeps only the ones containing 'error'.
.EXAMPLE
    Get-FileTail -Path app.log -Lines 0 -Follow
    Shows only new lines as they are written, skipping the existing content.
.NOTES
    Name: Get-FileTail
    Version: 2.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None
#>
function Get-FileTail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,

        [Parameter(Position = 1)]
        [Alias('n')]
        [int]$Lines = 10,

        [Parameter()]
        [Alias('f')]
        [switch]$Follow
    )

    Get-Content -Path $Path -Tail $Lines -Wait:$Follow
}

Set-Alias -Name tail -Value Get-FileTail
