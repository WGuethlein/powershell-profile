<#
.SYNOPSIS
    Returns AD users from a selected OU with chosen attributes, optionally exporting a CSV.
.DESCRIPTION
    Queries one of the configured OUs (Active, Departed, CR, India) at immediate-child scope,
    resolves the Manager attribute to a SamAccountName, and returns one object per user.
    With -Export the same rows are also written to a CSV. OU distinguished names come from the
    WyattTools config (OUs key).
.PARAMETER Ou
    Which configured OU to query: Active, Departed, CR, or India.
.PARAMETER Properties
    Attributes to return. Manager is resolved to SamAccountName.
.PARAMETER Export
    Write results to ADUserReport_<Ou>_yyyyMMdd_HHmm.csv in the configured export directory.
.EXAMPLE
    Get-ADUserReport -Ou Active | Format-Table
.EXAMPLE
    Get-ADUserReport -Ou Departed -Properties SamAccountName,Manager -Export
.EXAMPLE
    Get-ADUserReport -Ou Active -Properties SamAccountName,Name,Title,Department,Manager | Where-Object { -not $_.Manager }
    Finds active users with no manager set.
.EXAMPLE
    Get-ADUserReport -Ou Active | Group-Object Department | Sort-Object Count -Descending
    Counts users per department in the Active OU.
.EXAMPLE
    Get-ADUserReport -Ou India -Properties SamAccountName,Enabled,Title -Export
    Exports a trimmed column set for the India OU.
.NOTES
    Name: Get-ADUserReport
    Version: 2.1.0
    Author: WGuethlein
    Date: 2026-10-04
    Prerequisites: ActiveDirectory module (RSAT), rights to read AD
#>
function Get-ADUserReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Active', 'Departed', 'CR', 'India')]
        [string]$Ou,

        [Parameter()]
        [string[]]$Properties = @(
            'SamAccountName', 'Name', 'Enabled',
            'Company', 'Department', 'Title', 'Manager'
        ),

        [Parameter()]
        [switch]$Export
    )

    Assert-Module -Name ActiveDirectory

    $searchBase = (Get-WyattConfig).OUs[$Ou]
    if (-not $searchBase) { throw "No DN configured for OU '$Ou' (config key OUs.$Ou)." }

    # OneLevel = immediate children only. SamAccountName/Name/Enabled are returned by default.
    $adProperties = @($Properties | Where-Object { $_ -ne 'SamAccountName' -and $_ -ne 'Enabled' -and $_ -ne 'Name' })

    # -Properties throws on an empty list, so only pass it when there is something to request.
    $propArgs = @{}
    if ($adProperties.Count -gt 0) { $propArgs['Properties'] = $adProperties }

    try {
        Write-Verbose "Querying $searchBase (OneLevel scope)."
        $users = Get-ADUser -SearchBase $searchBase -SearchScope OneLevel -Filter * @propArgs -ErrorAction Stop
    }
    catch {
        throw "AD query failed for '$Ou' ($searchBase): $($_.Exception.Message)"
    }

    if (-not $users) {
        Write-Warning "No users found in $searchBase."
        return
    }

    # Cache manager DN -> SamAccountName lookups to avoid repeat queries.
    $managerCache = @{}

    $report = foreach ($user in $users) {
        $row = [ordered]@{}
        foreach ($prop in $Properties) {
            if ($prop -ne 'Manager') {
                $row[$prop] = $user.$prop
                continue
            }
            $mgrDn = $user.Manager
            if ([string]::IsNullOrWhiteSpace($mgrDn)) {
                $row['Manager'] = $null
                continue
            }
            if (-not $managerCache.ContainsKey($mgrDn)) {
                try {
                    $managerCache[$mgrDn] = (Get-ADUser -Identity $mgrDn -ErrorAction Stop).SamAccountName
                }
                catch {
                    # Manager object outside scope or deleted; fall back to DN.
                    Write-Verbose "Could not resolve manager '$mgrDn': $($_.Exception.Message)"
                    $managerCache[$mgrDn] = $mgrDn
                }
            }
            $row['Manager'] = $managerCache[$mgrDn]
        }
        [PSCustomObject]$row
    }

    if ($Export) {
        $path = Join-Path (Get-ExportDirectory) ('ADUserReport_{0}_{1}.csv' -f $Ou, (Get-Date -Format 'yyyyMMdd_HHmm'))
        $report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Host "Exported to $path" -ForegroundColor Cyan
    }

    $report
}
