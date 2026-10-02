<#
.SYNOPSIS
    Compares the direct group memberships of two AD users.
.DESCRIPTION
    Reads MemberOf for both users (direct groups only, primary group excluded) and returns one
    object per group in either list: Group, InReference, InDifference. Prints a short summary of
    groups unique to each user.
.PARAMETER ReferenceUser
    SamAccountName, UPN, or email of the reference user.
.PARAMETER DifferenceUser
    SamAccountName, UPN, or email of the user to compare against the reference.
.EXAMPLE
    Compare-ADUserGroups -ReferenceUser jdoe -DifferenceUser asmith | Where-Object { -not $_.InDifference }
.NOTES
    Name: Compare-ADUserGroups
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: ActiveDirectory module
#>
function Compare-ADUserGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ReferenceUser,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$DifferenceUser
    )

    Assert-Module -Name ActiveDirectory

    $ref  = Resolve-ADUserIdentity -User $ReferenceUser -Properties MemberOf
    $diff = Resolve-ADUserIdentity -User $DifferenceUser -Properties MemberOf
    if ($null -eq $ref.ADUser)  { Write-Error "Reference user not found: $ReferenceUser ($($ref.Error))"; return }
    if ($null -eq $diff.ADUser) { Write-Error "Difference user not found: $DifferenceUser ($($diff.Error))"; return }

    # Compare by group DN, display by CN (first RDN, unescaped).
    $refDns  = @($ref.ADUser.MemberOf)
    $diffDns = @($diff.ADUser.MemberOf)
    $allDns  = @($refDns + $diffDns | Where-Object { $_ } | Sort-Object -Unique)

    $results = foreach ($dn in $allDns) {
        $name = ((($dn -split '(?<!\\),')[0]) -replace '^CN=', '') -replace '\\(.)', '$1'
        [PSCustomObject]@{
            Group        = $name
            InReference  = [bool]($refDns -contains $dn)
            InDifference = [bool]($diffDns -contains $dn)
        }
    }
    $results = @($results | Sort-Object Group)

    $onlyRef  = @($results | Where-Object { $_.InReference -and -not $_.InDifference }).Count
    $onlyDiff = @($results | Where-Object { $_.InDifference -and -not $_.InReference }).Count
    $both     = @($results | Where-Object { $_.InReference -and $_.InDifference }).Count
    Write-Host "Only in $($ref.ADUser.SamAccountName): $onlyRef" -ForegroundColor Yellow
    Write-Host "Only in $($diff.ADUser.SamAccountName): $onlyDiff" -ForegroundColor Cyan
    Write-Host "In both: $both" -ForegroundColor Gray

    $results
}
