<#
.SYNOPSIS
    Describes where an ACE applies, from its InheritanceFlags and PropagationFlags.
.DESCRIPTION
    Returns text such as 'This folder, subfolders and files' or 'Subfolders only'. Appends
    ' (one level)' when NoPropagateInherit is set.
.PARAMETER InheritanceFlags
    InheritanceFlags text, for example 'ContainerInherit, ObjectInherit'.
.PARAMETER PropagationFlags
    PropagationFlags text, for example 'InheritOnly'.
.EXAMPLE
    ConvertTo-FileAppliesTo -InheritanceFlags 'ContainerInherit' -PropagationFlags 'InheritOnly'
    Returns 'Subfolders only'.
.NOTES
    Name: ConvertTo-FileAppliesTo
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-19
    Prerequisites: None
#>
function ConvertTo-FileAppliesTo {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [string]$InheritanceFlags,

        [Parameter(Position = 1)]
        [string]$PropagationFlags
    )

    $ci = $InheritanceFlags -like '*ContainerInherit*'
    $oi = $InheritanceFlags -like '*ObjectInherit*'
    $io = $PropagationFlags -like '*InheritOnly*'

    if ($ci -and $oi -and $io)  { $text = 'Subfolders and files only' }
    elseif ($ci -and $io)       { $text = 'Subfolders only' }
    elseif ($oi -and $io)       { $text = 'Files only' }
    elseif ($ci -and $oi)       { $text = 'This folder, subfolders and files' }
    elseif ($ci)                { $text = 'This folder and subfolders' }
    elseif ($oi)                { $text = 'This folder and files' }
    else                        { $text = 'This folder only' }

    if ($PropagationFlags -like '*NoPropagateInherit*') { $text += ' (one level)' }
    return $text
}
