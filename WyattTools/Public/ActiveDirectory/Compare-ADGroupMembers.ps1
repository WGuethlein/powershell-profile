<#
.SYNOPSIS
    Lists AD group members, combined with other groups using -Or, -And and -Not.
.DESCRIPTION
    Starts with the users in -Group plus any -Or groups, keeps only users who are also in every
    -And group, then drops users in any -Not group. With none of those, it lists -Group's users.
    Nested membership counts by default (a user in a group inside the group is a member); use
    -DirectOnly to use direct members only. Groups are matched by name or SamAccountName. Users
    are found with an LDAP memberOf query, so large groups (over the 5000-member
    Get-ADGroupMember limit) work and no per-user lookups are needed.
.PARAMETER Group
    The starting group.
.PARAMETER Not
    Groups to exclude: a user in any of them is left out of the results.
.PARAMETER And
    Groups the user must also be in (all of them).
.PARAMETER Or
    Groups whose users are added to -Group's users. This widens the starting set; it does not
    add to -Not. To exclude several groups, list them all after -Not.
.PARAMETER DirectOnly
    Use direct members only instead of including nested groups.
.PARAMETER Export
    Write results to GroupCompare_yyyyMMdd_HHmm.csv in the configured export directory.
.EXAMPLE
    Compare-ADGroupMembers -Group 'VPN-Users' -Not 'MFA-Enrolled'
    Users in VPN-Users who are not in MFA-Enrolled.
.EXAMPLE
    Compare-ADGroupMembers -Group 'App-Users' -And 'Remote-Staff'
    Users in both groups.
.EXAMPLE
    Compare-ADGroupMembers -Group 'Office-A' -Or 'Office-B' -Not 'Laptop-Users' -Export
    Users in Office-A or Office-B who are not in Laptop-Users, saved to CSV.
.EXAMPLE
    Compare-ADGroupMembers 'Staff' 'Office-A', 'Office-B'
    Positional form: users in Staff who are in neither Office-A nor Office-B.
.EXAMPLE
    Compare-ADGroupMembers -Group 'Senior-Leaders' -Not 'LIC-Copilot-A', 'LIC-Copilot-B' | Format-Table
    Senior leaders who have neither Copilot license group. Several -Not groups means "in none of them".
.EXAMPLE
    Compare-ADGroupMembers -Group 'Senior-Leaders' -Not 'LIC-Copilot-A' -Or 'LIC-Copilot-B'
    Common mistake: this is (Senior-Leaders or LIC-Copilot-B) not in LIC-Copilot-A, so LIC-Copilot-B
    members who are not senior leaders show up too. Use the previous example instead. Prints a warning.
.EXAMPLE
    Compare-ADGroupMembers -Group 'Senior-Leaders' -Or 'Directors' -And 'Remote-Staff' -Not 'MFA-Enrolled'
    Senior leaders or directors who are remote staff and not MFA enrolled. Order of evaluation is
    always: -Group plus -Or, then -And, then -Not, regardless of the order typed.
.EXAMPLE
    Compare-ADGroupMembers -Group 'Senior-Leaders' -And 'LIC-Copilot-A', 'LIC-Copilot-B'
    Senior leaders who are in BOTH license groups (double-licensed).
.EXAMPLE
    Compare-ADGroupMembers -Group 'VPN-Users' -Not 'MFA-Enrolled' -DirectOnly | Where-Object { -not $_.Enabled }
    Direct members of VPN-Users, not in MFA-Enrolled, filtered to disabled accounts.
.NOTES
    Name: Compare-ADGroupMembers
    Version: 1.3.0
    Author: WGuethlein
    Date: 2026-10-06
    Prerequisites: ActiveDirectory module
#>
function Compare-ADGroupMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Group,

        [Parameter(Position = 1)]
        [string[]]$Not,

        [string[]]$And,

        [string[]]$Or,

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

    # Resolves a list of names; returns $null if any of them fails so the run stops.
    $resolveAll = {
        param([string[]]$Names)
        $groups = @(foreach ($n in @($Names | Where-Object { $_ })) { & $resolveGroup $n })
        $groups = @($groups | Where-Object { $_ })
        if ($groups.Count -ne @($Names | Where-Object { $_ }).Count) { return $null }
        , $groups
    }

    # Case-insensitive set of the DNs of every user in the given groups.
    $dnSet = {
        param($Groups)
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($g in $Groups) {
            foreach ($u in @(& $getUsers $g)) { $null = $set.Add($u.DistinguishedName) }
        }
        , $set
    }

    $source = & $resolveGroup $Group
    if ($null -eq $source) { return }
    $orGroups = & $resolveAll $Or
    $andGroups = & $resolveAll $And
    $notGroups = & $resolveAll $Not
    if ($null -eq $orGroups -or $null -eq $andGroups -or $null -eq $notGroups) { return }

    # "-Not A -Or B" reads like "not in A or B" but means "(Group or B) not in A".
    if ($orGroups.Count -gt 0 -and $notGroups.Count -gt 0) {
        Write-Warning ("-Or ADDS users from '{0}' to the results. To exclude users in several groups, list them all after -Not: -Not 'A', 'B'." -f (@($orGroups | ForEach-Object { $_.Name }) -join "', '"))
    }

    # -Group plus -Or groups, de-duplicated by DN.
    $users = @{}
    foreach ($g in @($source) + $orGroups) {
        foreach ($u in @(& $getUsers $g)) { $users[$u.DistinguishedName] = $u }
    }
    $candidates = @($users.Values)

    # -And: must be in every one of these groups.
    foreach ($g in $andGroups) {
        $inGroup = & $dnSet @(, $g)
        $candidates = @($candidates | Where-Object { $inGroup.Contains($_.DistinguishedName) })
    }

    # -Not: drop anyone in any of these groups.
    if ($notGroups.Count -gt 0) {
        $excluded = & $dnSet $notGroups
        $candidates = @($candidates | Where-Object { -not $excluded.Contains($_.DistinguishedName) })
    }

    $results = @($candidates | Sort-Object DisplayName | ForEach-Object {
            [pscustomobject]@{
                Name              = $_.DisplayName
                SamAccountName    = $_.SamAccountName
                UserPrincipalName = $_.UserPrincipalName
                Department        = $_.Department
                Enabled           = $_.Enabled
            }
        })

    # Summary, e.g. "Office-A or Office-B, and in Staff, not in Laptops: 12 users (including nested)"
    $desc = (@($source.Name) + @($orGroups | ForEach-Object { $_.Name })) -join ' or '
    if ($andGroups.Count -gt 0) { $desc += ', and in ' + (@($andGroups | ForEach-Object { $_.Name }) -join ' and ') }
    if ($notGroups.Count -gt 0) { $desc += ', not in ' + (@($notGroups | ForEach-Object { $_.Name }) -join ' or ') }
    $scope = 'including nested'
    if ($DirectOnly) { $scope = 'direct only' }
    Write-Host "${desc}: $($results.Count) users ($scope)" -ForegroundColor Cyan

    if ($Export) {
        $path = Join-Path (Get-ExportDirectory) ('GroupCompare_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmm'))
        $results | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Host "Exported to $path" -ForegroundColor Cyan
    }

    $results
}
