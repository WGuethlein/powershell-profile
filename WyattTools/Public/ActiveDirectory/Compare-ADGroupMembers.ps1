<#
.SYNOPSIS
    Lists users who are in one AD group but not in another.
.DESCRIPTION
    Returns every user in -Group who is not in any of the -Not groups. Nested membership counts
    on both sides by default (a user in a group inside the group is a member); use -DirectOnly
    to compare direct members only. Groups are matched by name or SamAccountName. Users are
    found with an LDAP memberOf query, so large groups (over the 5000-member
    Get-ADGroupMember limit) work and no per-user lookups are needed.
.PARAMETER Group
    The group whose members you want to check.
.PARAMETER Not
    One or more groups to exclude: a user in any of them is left out of the results.
.PARAMETER DirectOnly
    Compare direct members only instead of including nested groups.
.PARAMETER Export
    Write results to GroupCompare_yyyyMMdd_HHmm.csv in the configured export directory.
.EXAMPLE
    Compare-ADGroupMembers -Group 'VPN-Users' -Not 'MFA-Enrolled'
.EXAMPLE
    Compare-ADGroupMembers 'Staff' 'Office-A', 'Office-B' -Export
.EXAMPLE
    Compare-ADGroupMembers -Group 'App-Users' -Not 'App-Admins' -DirectOnly | Where-Object Enabled
.NOTES
    Name: Compare-ADGroupMembers
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-04
    Prerequisites: ActiveDirectory module
#>
function Compare-ADGroupMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Group,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Not,

        [switch]$DirectOnly,

        [switch]$Export
    )

    Assert-Module -Name ActiveDirectory

    # Finds exactly one group by Name or SamAccountName; returns $null (with an error) otherwise.
    $resolveGroup = {
        param([string]$Name)
        $safe = $Name.Replace("'", "''")
        $found = @(Get-ADGroup -Filter "Name -eq '$safe' -or SamAccountName -eq '$safe'" -ErrorAction Stop)
        if ($found.Count -ne 1) {
            Write-Error "Expected one group named '$Name', found $($found.Count)."
            return $null
        }
        $found[0]
    }

    # Users whose memberOf includes the group. The 1.2.840.113556.1.4.1941 matching rule
    # (LDAP_MATCHING_RULE_IN_CHAIN) makes the match transitive, so nested members count.
    # DN characters that are special in LDAP filters are hex-escaped; backslash goes first.
    $getUsers = {
        param($AdGroup)
        $dn = $AdGroup.DistinguishedName.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
        $rule = ':1.2.840.113556.1.4.1941:'
        if ($DirectOnly) { $rule = '' }
        Get-ADUser -LDAPFilter "(memberOf$rule=$dn)" -Properties DisplayName, Department -ErrorAction Stop
    }

    $source = & $resolveGroup $Group
    if ($null -eq $source) { return }
    $excludeGroups = foreach ($name in $Not) { & $resolveGroup $name }
    $excludeGroups = @($excludeGroups | Where-Object { $_ })
    if ($excludeGroups.Count -ne $Not.Count) { return }

    $members = @(& $getUsers $source)

    # DNs of everyone in any -Not group, for a fast case-insensitive lookup.
    $excluded = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $excludeGroups) {
        foreach ($u in @(& $getUsers $g)) { $null = $excluded.Add($u.DistinguishedName) }
    }

    $results = @($members | Where-Object { -not $excluded.Contains($_.DistinguishedName) } | Sort-Object DisplayName | ForEach-Object {
            [pscustomobject]@{
                Name              = $_.DisplayName
                SamAccountName    = $_.SamAccountName
                UserPrincipalName = $_.UserPrincipalName
                Department        = $_.Department
                Enabled           = $_.Enabled
            }
        })

    $scope = 'including nested'
    if ($DirectOnly) { $scope = 'direct only' }
    Write-Host "$($source.Name): $($members.Count) users ($scope). Not in $($excludeGroups.Name -join ', '): $($results.Count)" -ForegroundColor Cyan

    if ($Export) {
        $path = Join-Path (Get-ExportDirectory) ('GroupCompare_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmm'))
        $results | Export-Csv -Path $path -NoTypeInformation
        Write-Host "Exported to $path" -ForegroundColor Cyan
    }

    $results
}
