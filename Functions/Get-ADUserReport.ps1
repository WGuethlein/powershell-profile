<#
.SYNOPSIS
    Exports AD users from a selected DLZ OU with chosen attributes to console and CSV.

.DESCRIPTION
    Dot-sourceable function that queries one of four predefined DLZ OUs (Active,
    Departed, CR, India) at immediate-child scope, resolves the Manager attribute
    to a SamAccountName, writes results to the console, and exports a CSV to the
    user's Documents folder.

.NOTES
    Name        : Get-DlzUserReport
    Version     : 1.0
    Author      : Wyatt
    Date        : 2026-07-13
    Prereqs     : PowerShell 5.1, ActiveDirectory module (RSAT), rights to read AD
    Usage       : . .\Get-DlzUserReport.ps1
                  Get-DlzUserReport -Ou Active
                  Get-DlzUserReport -Ou Departed -Properties SamAccountName,Manager
#>

function Get-DlzUserReport {
    [CmdletBinding()]
    param(
        # Which predefined OU to query.
        [Parameter(Mandatory)]
        [ValidateSet('Active', 'Departed', 'CR', 'India')]
        [string]$Ou,

        # Attributes to return. Manager is resolved to SamAccountName.
        [Parameter()]
        [string[]]$Properties = @(
            'SamAccountName', 'Name', 'Enabled',
            'Company', 'Department', 'Title', 'Manager'
        ),

        # Override the default CSV output directory.
        [Parameter()]
        [string]$OutputDirectory = (Join-Path $env:USERPROFILE 'Documents')
    )

    #--- Configuration -------------------------------------------------------
    $baseDn = 'OU=DLZ Accounts,DC=dlzcorp,DC=com'

    # Map friendly OU choice to its distinguished name.
    $ouMap = @{
        'Active'   = "OU=Active,$baseDn"
        'Departed' = "OU=Departed,$baseDn"
        'CR'       = "OU=CR-Users,OU=CR-Office,$baseDn"
        'India'    = "OU=India,$baseDn"
    }
    $searchBase = $ouMap[$Ou]

    #--- Preflight checks ----------------------------------------------------
    # Verify the ActiveDirectory module is available before doing anything else.
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not found. Install RSAT AD tools."
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    if (-not (Test-Path -Path $OutputDirectory)) {
        throw "Output directory does not exist: $OutputDirectory"
    }

    #--- Query ---------------------------------------------------------------
    # OneLevel = immediate children only, no nested OUs.
    # Request Manager explicitly so we can resolve it; drop it from the
    # Get-ADUser property list only if the caller didn't ask for it.
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

    #--- Shape output --------------------------------------------------------
    # Cache manager DN -> SamAccountName lookups to avoid repeat queries.
    $managerCache = @{}

    $report = foreach ($user in $users) {
        $row = [ordered]@{}

        foreach ($prop in $Properties) {
            if ($prop -eq 'Manager') {
                $mgrDn = $user.Manager
                if ([string]::IsNullOrWhiteSpace($mgrDn)) {
                    $row['Manager'] = $null
                }
                elseif ($managerCache.ContainsKey($mgrDn)) {
                    $row['Manager'] = $managerCache[$mgrDn]
                }
                else {
                    try {
                        $mgr = Get-ADUser -Identity $mgrDn -ErrorAction Stop
                        $managerCache[$mgrDn] = $mgr.SamAccountName
                        $row['Manager'] = $mgr.SamAccountName
                    }
                    catch {
                        # Manager object outside scope or deleted; fall back to DN.
                        Write-Verbose "Could not resolve manager '$mgrDn': $($_.Exception.Message)"
                        $managerCache[$mgrDn] = $mgrDn
                        $row['Manager'] = $mgrDn
                    }
                }
            }
            else {
                $row[$prop] = $user.$prop
            }
        }

        [PSCustomObject]$row
    }

    #--- Console output ------------------------------------------------------
    $report | Format-Table -AutoSize

    #--- CSV export ----------------------------------------------------------
    $stamp    = Get-Date -Format 'yyyyMMdd'
    $fileName = "ADUserReport_${Ou}_${stamp}.csv"
    $csvPath  = Join-Path $OutputDirectory $fileName

    try {
        $report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "Exported $($report.Count) users to $csvPath" -ForegroundColor Green
    }
    catch {
        throw "CSV export failed to '$csvPath': $($_.Exception.Message)"
    }
}