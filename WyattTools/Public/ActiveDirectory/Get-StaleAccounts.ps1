<#
.SYNOPSIS
    Reports user and/or computer accounts that have not logged on recently.
.DESCRIPTION
    Queries AD (read-only) and computes LastLogon from LastLogonTimestamp. An account is stale if
    its LastLogon is older than the cutoff, or it never logged on and was created before the
    cutoff. Note: LastLogonTimestamp replicates with up to ~14 days lag, so use Days >= 14.
.PARAMETER Days
    Inactivity threshold in days. Default: StaleDays from config, fallback 90.
.PARAMETER Type
    User, Computer, or Both (default).
.PARAMETER IncludeDisabled
    Include disabled accounts (default: enabled only).
.PARAMETER Export
    Write results to StaleAccounts_yyyyMMdd.csv in the export directory.
.EXAMPLE
    Get-StaleAccounts -Days 120 -Type Computer
.EXAMPLE
    Get-StaleAccounts -IncludeDisabled -Export
.EXAMPLE
    Get-StaleAccounts -Type User -Days 180 | Sort-Object DaysInactive -Descending | Select-Object -First 25
    Shows the 25 longest-inactive enabled users past 180 days.
.EXAMPLE
    Get-StaleAccounts -Type Computer | Group-Object { $_.DistinguishedName -replace '^CN=[^,]+,' } | Sort-Object Count -Descending
    Counts stale computers per OU to see where the clutter is.
.EXAMPLE
    Get-StaleAccounts -Days 365 -Export | Where-Object { $_.LastLogon -eq $null }
    Exports the year-stale list and also shows accounts that have never logged on.
.NOTES
    Name: Get-StaleAccounts
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: ActiveDirectory module
#>
function Get-StaleAccounts {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1, 3650)]
        [int]$Days,

        [Parameter()]
        [ValidateSet('User', 'Computer', 'Both')]
        [string]$Type = 'Both',

        [Parameter()]
        [switch]$IncludeDisabled,

        [Parameter()]
        [switch]$Export
    )

    Assert-Module -Name ActiveDirectory

    if (-not $PSBoundParameters.ContainsKey('Days')) {
        $Days = 90
        $cfgDays = (Get-WyattConfig).StaleDays
        if ($cfgDays -and [int]$cfgDays -gt 0) { $Days = [int]$cfgDays }
    }
    $cutoff = (Get-Date).AddDays(-$Days)
    Write-Verbose "Cutoff: $cutoff ($Days days)"

    $filter = '*'
    if (-not $IncludeDisabled) { $filter = "Enabled -eq `$true" }

    $targets = @()
    if ($Type -ne 'Computer') { $targets += 'User' }
    if ($Type -ne 'User') { $targets += 'Computer' }

    $results = foreach ($t in $targets) {
        $props = 'LastLogonTimestamp', 'whenCreated', 'Description'
        if ($t -eq 'Computer') {
            $props += 'OperatingSystem'
            $objects = Get-ADComputer -Filter $filter -Properties $props
        }
        else {
            $objects = Get-ADUser -Filter $filter -Properties $props
        }

        foreach ($o in $objects) {
            $lastLogon = $null
            if ($o.LastLogonTimestamp -and [int64]$o.LastLogonTimestamp -gt 0) {
                $lastLogon = [datetime]::FromFileTime([int64]$o.LastLogonTimestamp)
            }

            if ($null -ne $lastLogon) { $stale = ($lastLogon -lt $cutoff) }
            else { $stale = ($o.whenCreated -lt $cutoff) }
            if (-not $stale) { continue }

            $ref = $lastLogon
            if ($null -eq $ref) { $ref = $o.whenCreated }

            [PSCustomObject]@{
                Type              = $t
                Name              = $o.Name
                SamAccountName    = $o.SamAccountName
                Enabled           = $o.Enabled
                LastLogon         = $lastLogon
                DaysInactive      = [int]((Get-Date) - $ref).TotalDays
                whenCreated       = $o.whenCreated
                DistinguishedName = $o.DistinguishedName
            }
        }
    }
    $results = @($results | Sort-Object Type, @{ Expression = 'DaysInactive'; Descending = $true })

    Write-Host "Stale accounts (>$Days days): $($results.Count)" -ForegroundColor Cyan

    if ($Export) {
        $path = Join-Path (Get-ExportDirectory) ("StaleAccounts_{0}.csv" -f (Get-Date -Format 'yyyyMMdd'))
        $results | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Host "Exported to $path" -ForegroundColor Green
    }

    $results
}
