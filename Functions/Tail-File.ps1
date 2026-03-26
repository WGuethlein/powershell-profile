<#
.SYNOPSIS
    Mimics Linux tail -f behavior in PowerShell.

.DESCRIPTION
    Displays the last N lines of a file and watches for new content,
    behaving like Linux 'tail -f'. Defaults to 10 lines per the Linux tail standard.

.PARAMETER Path
    The file to tail.

.PARAMETER Lines
    Number of lines to show from the end of the file. Defaults to 10.

.PARAMETER Wait
    If specified, continues watching the file for new content (like tail -f).
    This is the default behavior; pass -Wait:$false to disable it.

.EXAMPLE
    Tail-File app.log
    Tail-File app.log -n 50
    Tail-File app.log -n 50 -Wait:$false

#>
function Tail-File {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [string] $Path,

        [Parameter(Position = 1)]
        [Alias('n')]
        [int] $Lines = 10,

        [Parameter()]
        [Alias('f')]
        [switch] $Follow
    )

    Get-Content -Path $Path -Tail $Lines -Wait:$Follow
}

Set-Alias -Name tail -Value Tail-File