<#
.SYNOPSIS
    Exports AD users from a selected OU with chosen attributes to console and CSV.
.DESCRIPTION
    Queries one of the configured OUs (Active, Departed, CR, India) at immediate-child scope,
    resolves the Manager attribute to a SamAccountName, prints the results, and exports a CSV.
    OU distinguished names come from the WyattTools config (OUs key).
.PARAMETER Ou
    Which configured OU to query: Active, Departed, CR, or India.
.PARAMETER Properties
    Attributes to return. Manager is resolved to SamAccountName.
.PARAMETER OutputDirectory
    CSV output directory. Default: ExportDirectory from config, or the current location.
.EXAMPLE
    Get-ADUserReport -Ou Active
.EXAMPLE
    Get-ADUserReport -Ou Departed -Properties SamAccountName,Manager
.NOTES
    Name: Get-ADUserReport
    Version: 2.0.0
    Author: WGuethlein
    Date: 2026-10-02
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
        [string]$OutputDirectory
    )

    Assert-Module -Name ActiveDirectory

    $searchBase = (Get-WyattConfig).OUs[$Ou]
    if (-not $searchBase) { throw "No DN configured for OU '$Ou' (config key OUs.$Ou)." }

    if (-not $OutputDirectory) { $OutputDirectory = Get-ExportDirectory }
    if (-not (Test-Path -Path $OutputDirectory)) {
        throw "Output directory does not exist: $OutputDirectory"
    }

    # OneLevel = immediate children only. SamAccountName/Name/Enabled are returned by default.
    $adProperties = $Properties | Where-Object { $_ -ne 'SamAccountName' -and $_ -ne 'Enabled' -and $_ -ne 'Name' }

    try {
        Write-Verbose "Querying $searchBase (OneLevel scope)."
        $users = Get-ADUser -SearchBase $searchBase -SearchScope OneLevel -Filter * -Properties $adProperties -ErrorAction Stop
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

    $report | Format-Table -AutoSize | Out-Host

    $csvPath = Join-Path $OutputDirectory "ADUserReport_${Ou}_$(Get-Date -Format 'yyyyMMdd').csv"
    try {
        $report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "Exported $(@($report).Count) users to $csvPath" -ForegroundColor Green
    }
    catch {
        throw "CSV export failed to '$csvPath': $($_.Exception.Message)"
    }
}
