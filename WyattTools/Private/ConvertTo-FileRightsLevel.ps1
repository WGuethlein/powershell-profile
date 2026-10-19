<#
.SYNOPSIS
    Converts an NTFS access mask to a friendly level (FullControl, Modify, Read, ...).
.DESCRIPTION
    Maps generic bits (GENERIC_ALL/READ/WRITE/EXECUTE) to specific rights, ignores Synchronize,
    then returns the highest standard level the mask covers: FullControl, Modify, ReadAndExecute,
    Read or Write. Anything else is 'Special (<FileSystemRights names>)'.
.PARAMETER Mask
    Access mask as an int64 (as stored in the index; may be the unsigned form of a negative int).
.EXAMPLE
    ConvertTo-FileRightsLevel -Mask 1179817
    Returns ReadAndExecute.
.NOTES
    Name: ConvertTo-FileRightsLevel
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-19
    Prerequisites: None
#>
function ConvertTo-FileRightsLevel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [int64]$Mask
    )

    # Work in unsigned 32-bit space; PS 5.1 treats 0x80000000 as a negative int, so use int64 literals.
    $m = $Mask -band [int64]4294967295
    $genericAll     = [int64]268435456   # 0x10000000
    $genericExecute = [int64]536870912   # 0x20000000
    $genericWrite   = [int64]1073741824  # 0x40000000
    $genericRead    = [int64]2147483648  # 0x80000000
    $sync           = [int64]1048576     # 0x100000

    if ($m -band $genericAll)     { $m = $m -bor [int64]0x1F01FF }
    if ($m -band $genericRead)    { $m = $m -bor [int64]0x120089 }
    if ($m -band $genericWrite)   { $m = $m -bor [int64]0x120116 }
    if ($m -band $genericExecute) { $m = $m -bor [int64]0x1200A0 }
    $m = $m -band (-bnot ($genericAll -bor $genericExecute -bor $genericWrite -bor $genericRead))
    $m = $m -band (-bnot $sync)

    # Standard levels with Synchronize removed.
    $levels = @(
        @{ Name = 'FullControl';    Bits = ([int64]0x1F01FF -band (-bnot $sync)) }
        @{ Name = 'Modify';         Bits = ([int64]0x1301BF -band (-bnot $sync)) }
        @{ Name = 'ReadAndExecute'; Bits = ([int64]0x1200A9 -band (-bnot $sync)) }
        @{ Name = 'Read';           Bits = ([int64]0x120089 -band (-bnot $sync)) }
        @{ Name = 'Write';          Bits = [int64]0x116 }
    )
    foreach ($level in $levels) {
        if (($m -band $level.Bits) -eq $level.Bits) { return $level.Name }
    }

    $names = ([System.Security.AccessControl.FileSystemRights][int]$m).ToString()
    return "Special ($names)"
}
