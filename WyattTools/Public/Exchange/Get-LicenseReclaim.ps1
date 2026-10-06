<#
.SYNOPSIS
    Finds Microsoft 365 licenses that could be reclaimed from disabled or inactive users.
.DESCRIPTION
    Reads every user from Entra ID via Graph and reports licensed users that fall into one of
    three Reasons (first match wins):
      Disabled         - the account is disabled (accountEnabled = false).
      Never signed in  - no sign-in data at all and the account was created more than -Days ago.
                         Accounts created within the last -Days with no sign-in are not reported.
      Inactive         - the last sign-in is older than -Days.
    Last sign-in is signInActivity.lastSuccessfulSignInDateTime. Microsoft did not backfill that
    value before Dec 2023, so when it is empty the later of lastSignInDateTime and
    lastNonInteractiveSignInDateTime is used instead.
    Prerequisite: signInActivity needs an Entra ID P1 (or higher) license in the tenant and the
    AuditLog.Read.All Graph scope with admin consent (plus User.Read.All or Directory.Read.All).
    Without them Graph answers 403 and this function throws an explanatory error.
    Licenses are matched by SKU part number (for example ENTERPRISEPACK = Office 365 E3). Run
    Get-GroupLicenseGap -ListSkus to see the part numbers in this tenant.
.PARAMETER Days
    Inactivity threshold in days (1-3650). Default: StaleDays from config, fallback 90.
.PARAMETER SkuPartNumber
    Only consider users holding at least one of these SKU part numbers. Unknown part numbers
    are warned about and ignored. Candidates still show all of their licenses.
.PARAMETER Export
    Write results to LicenseReclaim_yyyyMMdd_HHmm.csv in the configured export directory.
.EXAMPLE
    Get-LicenseReclaim
.EXAMPLE
    Get-LicenseReclaim -SkuPartNumber ENTERPRISEPACK
.EXAMPLE
    Get-LicenseReclaim -Days 60 -Export
.EXAMPLE
    Get-LicenseReclaim -SkuPartNumber 'SPE_E3', 'ENTERPRISEPACK' -Days 120 | Where-Object Reason -eq 'Disabled'
    Disabled accounts that still hold one of two E3 SKUs (the -Days value does not affect disabled accounts).
.EXAMPLE
    Get-LicenseReclaim | Where-Object Reason -eq 'Inactive' | Sort-Object DaysInactive -Descending | Select-Object -First 10
    The ten longest-inactive licensed users.
.EXAMPLE
    Get-LicenseReclaim -Days 180 | Get-M365UserInfo | Format-List DisplayName, LastSignIn, Licenses, LicenseErrors
    Look up the full account details of each reclaim candidate before removing licenses.
.NOTES
    Name: Get-LicenseReclaim
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-04
    Prerequisites: Microsoft.Graph.Authentication module; Entra ID P1; AuditLog.Read.All consent
#>
function Get-LicenseReclaim {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1, 3650)]
        [int]$Days,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$SkuPartNumber,

        [Parameter()]
        [switch]$Export
    )

    # Default threshold: config StaleDays, else 90 (same convention as Get-StaleAccounts).
    if (-not $PSBoundParameters.ContainsKey('Days')) {
        $Days = 90
        $cfgDays = (Get-WyattConfig).StaleDays
        if ($cfgDays -and [int]$cfgDays -gt 0) { $Days = [int]$cfgDays }
    }

    $null = Connect-M365 -Graph

    # GETs a Graph URI and follows @odata.nextLink until every page is read.
    $getAll = {
        param([string]$Uri)
        $headers = @{ ConsistencyLevel = 'eventual' }
        while ($Uri) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers $headers -OutputType PSObject -ErrorAction Stop
            foreach ($item in @($page.value)) { $item }
            $Uri = $page.'@odata.nextLink'
        }
    }

    # Converts a Graph timestamp (string or DateTime, depending on PS version) to UTC, or $null.
    $toUtc = {
        param($Value)
        if ($null -eq $Value -or "$Value" -eq '') { return $null }
        if ($Value -is [datetime]) {
            if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) {
                return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
            }
            return $Value.ToUniversalTime()
        }
        $parsed = [datetime]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
            return $parsed
        }
        return $null
    }

    # SKU part number <-> skuId lookups. assignedLicenses on a user only carries skuId.
    $skus = @(& $getAll 'https://graph.microsoft.com/v1.0/subscribedSkus')
    $skuIdByPart = @{}
    $partBySkuId = @{}
    foreach ($s in $skus) {
        $skuIdByPart[[string]$s.skuPartNumber] = [string]$s.skuId
        $partBySkuId[[string]$s.skuId] = [string]$s.skuPartNumber
    }

    # Optional SKU filter: resolve to ids, warn on unknown parts, stop if nothing valid remains.
    $wantedIds = @()
    if ($SkuPartNumber) {
        foreach ($part in $SkuPartNumber) {
            if ($skuIdByPart.ContainsKey($part)) { $wantedIds += $skuIdByPart[$part] }
            else { Write-Warning "SKU '$part' is not in this tenant. Run Get-GroupLicenseGap -ListSkus for valid part numbers." }
        }
        if ($wantedIds.Count -eq 0) { throw 'None of the given -SkuPartNumber values exist in this tenant.' }
    }

    $select = 'id,displayName,userPrincipalName,accountEnabled,assignedLicenses,signInActivity,createdDateTime,onPremisesSyncEnabled'
    $uri = "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=500"

    Write-Verbose 'Reading users from Graph.'
    try {
        $users = @(& $getAll $uri)
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = "$msg $($_.ErrorDetails.Message)" }
        if ($msg -match '403|Forbidden|Authorization_RequestDenied|premium|license') {
            throw "Graph refused the sign-in activity query. It needs the AuditLog.Read.All scope with admin consent and an Entra ID P1 (or higher) license in the tenant. Original message: $msg"
        }
        throw
    }

    $nowUtc = (Get-Date).ToUniversalTime()
    $cutoff = $nowUtc.AddDays(-$Days)
    Write-Verbose "Cutoff: $cutoff UTC ($Days days)"

    $checked = 0
    $results = New-Object System.Collections.Generic.List[object]
    $skuCounts = @{}

    foreach ($user in $users) {
        $userSkuIds = @($user.assignedLicenses | ForEach-Object { [string]$_.skuId })
        if ($userSkuIds.Count -eq 0) { continue }
        if ($wantedIds.Count -gt 0 -and @($wantedIds | Where-Object { $userSkuIds -contains $_ }).Count -eq 0) { continue }
        $checked++

        # Prefer the successful sign-in; fall back to the later of the other two timestamps.
        $activity = $user.signInActivity
        $lastSignIn = $null
        $created = & $toUtc $user.createdDateTime
        if ($activity) {
            $lastSignIn = & $toUtc $activity.lastSuccessfulSignInDateTime
            if ($null -eq $lastSignIn) {
                foreach ($candidate in @((& $toUtc $activity.lastSignInDateTime), (& $toUtc $activity.lastNonInteractiveSignInDateTime))) {
                    if ($null -ne $candidate -and ($null -eq $lastSignIn -or $candidate -gt $lastSignIn)) { $lastSignIn = $candidate }
                }
            }
        }

        # First match wins: Disabled, Never signed in, Inactive.
        $reason = $null
        if ($user.accountEnabled -eq $false) { $reason = 'Disabled' }
        elseif ($null -eq $lastSignIn) {
            if ($null -ne $created -and $created -lt $cutoff) { $reason = 'Never signed in' }
        }
        elseif ($lastSignIn -lt $cutoff) { $reason = 'Inactive' }
        if (-not $reason) { continue }

        $lastLocal = ''
        $daysInactive = ''
        if ($null -ne $lastSignIn) {
            $lastLocal = $lastSignIn.ToLocalTime()
            $daysInactive = [int][math]::Floor(($nowUtc - $lastSignIn).TotalDays)
        }
        $createdLocal = ''
        if ($null -ne $created) { $createdLocal = $created.ToLocalTime() }

        $parts = @($userSkuIds | ForEach-Object {
                if ($partBySkuId.ContainsKey($_)) { $partBySkuId[$_] } else { $_ }
            } | Sort-Object)
        foreach ($p in $parts) { $skuCounts[$p] = 1 + [int]$skuCounts[$p] }

        $results.Add([pscustomobject]@{
            DisplayName       = $user.displayName
            UserPrincipalName = $user.userPrincipalName
            AccountEnabled    = $user.accountEnabled
            Reason            = $reason
            LastSignIn        = $lastLocal
            DaysInactive      = $daysInactive
            Created           = $createdLocal
            Licenses          = $parts -join ', '
        })
    }

    # Sort by Reason, then longest inactive first (blank = no sign-in data, sorts last).
    $sorted = @($results | Sort-Object -Property @{ Expression = 'Reason'; Descending = $false },
        @{ Expression = { if ($_.DaysInactive -eq '') { -1 } else { $_.DaysInactive } }; Descending = $true })

    Write-Host ("Licensed users checked: {0}  |  Reclaim candidates: {1}  |  Threshold: {2} days" -f $checked, $sorted.Count, $Days)
    if ($sorted.Count -gt 0) {
        $sorted | Group-Object Reason | Sort-Object Name |
            ForEach-Object { [pscustomobject]@{ Reason = $_.Name; Users = $_.Count } } |
            Format-Table -AutoSize | Out-String | Write-Host
        $skuCounts.Keys | Sort-Object |
            ForEach-Object { [pscustomobject]@{ SkuPartNumber = $_; Candidates = $skuCounts[$_] } } |
            Format-Table -AutoSize | Out-String | Write-Host
    }

    if ($Export) {
        $path = Join-Path (Get-ExportDirectory) ('LicenseReclaim_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmm'))
        $sorted | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Host "Exported to $path" -ForegroundColor Cyan
    }

    $sorted
}
