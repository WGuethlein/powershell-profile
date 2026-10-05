<#
.SYNOPSIS
    Lists members of a license group who do not have the license the group is meant to grant.
.DESCRIPTION
    For each group -> license pair, reads the group's members from Entra ID (nested members
    included, so synced on-prem AD groups work) and reports every user who does not have the
    expected SKU assigned. Licenses are matched by SKU part number (the "String ID" Microsoft
    publishes, for example ENTERPRISEPACK = Office 365 E3, EMS = Enterprise Mobility + Security
    E3). Run with -ListSkus to see the part numbers in this tenant and how many seats are free.
    With no group parameters, the pairs come from LicenseGroups in the WyattTools config.
    Connects to Graph if needed (needs User.Read.All, GroupMember.Read.All or Group.Read.All,
    and Organization.Read.All or Directory.Read.All).
.PARAMETER GroupName
    Display name of one group to check. Use with -SkuPartNumber.
.PARAMETER SkuPartNumber
    SKU part number(s) the group should grant. If several are given, any one counts as licensed.
.PARAMETER Map
    Hashtable of group display name -> SKU part number (or array of them). Defaults to
    LicenseGroups from the WyattTools config.
.PARAMETER ListSkus
    List the tenant's SKU part numbers with total, used and free seats, then stop.
.PARAMETER Export
    Write results to LicenseGap_yyyyMMdd_HHmm.csv in the configured export directory.
.PARAMETER ExcludeDisabled
    Leave out users whose account is disabled (accountEnabled is false). They are dropped before
    counting, so Members, Licensed and Missing in the summary all count only the remaining users.
.EXAMPLE
    Get-GroupLicenseGap -Export
.EXAMPLE
    Get-GroupLicenseGap -ExcludeDisabled
.EXAMPLE
    Get-GroupLicenseGap -GroupName 'LIC-Visio' -SkuPartNumber 'VISIOCLIENT'
.EXAMPLE
    Get-GroupLicenseGap -Map @{ 'LIC-E5' = 'SPE_E5'; 'LIC-Project' = 'PROJECTPROFESSIONAL' }
.EXAMPLE
    Get-GroupLicenseGap -ListSkus
.NOTES
    Name: Get-GroupLicenseGap
    Version: 1.1.0
    Author: WGuethlein
    Date: 2026-10-04
    Prerequisites: Microsoft.Graph.Authentication module
#>
function Get-GroupLicenseGap {
    [CmdletBinding(DefaultParameterSetName = 'Map')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Single')]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName,

        [Parameter(Mandatory, ParameterSetName = 'Single')]
        [ValidateNotNullOrEmpty()]
        [string[]]$SkuPartNumber,

        [Parameter(ParameterSetName = 'Map')]
        [hashtable]$Map,

        [Parameter(Mandatory, ParameterSetName = 'ListSkus')]
        [switch]$ListSkus,

        [Parameter(ParameterSetName = 'Single')]
        [Parameter(ParameterSetName = 'Map')]
        [switch]$Export,

        [Parameter(ParameterSetName = 'Single')]
        [Parameter(ParameterSetName = 'Map')]
        [switch]$ExcludeDisabled
    )

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

    # SKU part number <-> skuId lookups. assignedLicenses on a user only carries skuId.
    $skus = @(& $getAll 'https://graph.microsoft.com/v1.0/subscribedSkus')
    $skuIdByPart = @{}
    $partBySkuId = @{}
    foreach ($s in $skus) {
        $skuIdByPart[[string]$s.skuPartNumber] = [string]$s.skuId
        $partBySkuId[[string]$s.skuId] = [string]$s.skuPartNumber
    }

    if ($ListSkus) {
        return $skus | ForEach-Object {
            [pscustomobject]@{
                SkuPartNumber = $_.skuPartNumber
                Total         = $_.prepaidUnits.enabled
                Used          = $_.consumedUnits
                Free          = $_.prepaidUnits.enabled - $_.consumedUnits
            }
        } | Sort-Object SkuPartNumber
    }

    if ($PSCmdlet.ParameterSetName -eq 'Single') {
        $Map = @{ $GroupName = $SkuPartNumber }
    }
    elseif (-not $Map) {
        $Map = (Get-WyattConfig).LicenseGroups
        if (-not $Map -or $Map.Count -eq 0) {
            throw 'No groups given and LicenseGroups is empty in config.psd1. Use -GroupName/-SkuPartNumber or -Map.'
        }
    }

    $results = New-Object System.Collections.Generic.List[object]
    $summary = New-Object System.Collections.Generic.List[object]

    foreach ($name in $Map.Keys) {
        $wantedParts = @($Map[$name])

        # Resolve the expected SKU ids; skip the group if none exist in this tenant.
        $wantedIds = @()
        foreach ($part in $wantedParts) {
            if ($skuIdByPart.ContainsKey($part)) { $wantedIds += $skuIdByPart[$part] }
            else { Write-Warning "SKU '$part' is not in this tenant. Run Get-GroupLicenseGap -ListSkus for valid part numbers." }
        }
        if ($wantedIds.Count -eq 0) { continue }

        # Exact display-name match; single quotes are doubled for OData.
        $filter = [uri]::EscapeDataString("displayName eq '$($name.Replace("'", "''"))'")
        $groups = @(& $getAll "https://graph.microsoft.com/v1.0/groups?`$filter=$filter&`$select=id,displayName")
        if ($groups.Count -ne 1) {
            Write-Warning "Expected one group named '$name', found $($groups.Count). Skipping."
            continue
        }

        Write-Verbose "Reading members of '$name'."
        # The user cast needs ConsistencyLevel: eventual plus $count=true (advanced query).
        $select = 'id,displayName,userPrincipalName,accountEnabled,assignedLicenses,licenseAssignmentStates'
        $uri = "https://graph.microsoft.com/v1.0/groups/$($groups[0].id)/transitiveMembers/microsoft.graph.user?`$count=true&`$top=999&`$select=$select"
        $members = @(& $getAll $uri)
        # Drop disabled accounts up front so Members, Licensed and Missing stay consistent.
        if ($ExcludeDisabled) { $members = @($members | Where-Object { $_.accountEnabled -ne $false }) }

        $missingCount = 0
        foreach ($user in $members) {
            $userSkuIds = @($user.assignedLicenses | ForEach-Object { [string]$_.skuId })
            $hasLicense = @($wantedIds | Where-Object { $userSkuIds -contains $_ }).Count -gt 0
            if ($hasLicense) { continue }

            $missingCount++
            # A failed group-based assignment (for example CountViolation = out of seats) shows here.
            $errors = @($user.licenseAssignmentStates | Where-Object {
                    $wantedIds -contains [string]$_.skuId -and $_.state -eq 'Error'
                } | ForEach-Object { $_.error })
            $current = @($userSkuIds | ForEach-Object {
                    if ($partBySkuId.ContainsKey($_)) { $partBySkuId[$_] } else { $_ }
                })

            $results.Add([pscustomobject]@{
                Group             = $name
                ExpectedSku       = $wantedParts -join ', '
                DisplayName       = $user.displayName
                UserPrincipalName = $user.userPrincipalName
                AccountEnabled    = $user.accountEnabled
                AssignmentError   = ($errors | Select-Object -Unique) -join ', '
                CurrentLicenses   = ($current | Sort-Object) -join ', '
            })
        }

        $free = 0
        foreach ($s in $skus) {
            if ($wantedIds -contains [string]$s.skuId) { $free += $s.prepaidUnits.enabled - $s.consumedUnits }
        }
        $summary.Add([pscustomobject]@{
            Group       = $name
            ExpectedSku = $wantedParts -join ', '
            Members     = $members.Count
            Licensed    = $members.Count - $missingCount
            Missing     = $missingCount
            FreeSeats   = $free
        })
    }

    $summary | Format-Table -AutoSize | Out-String | Write-Host

    if ($Export) {
        $path = Join-Path (Get-ExportDirectory) ('LicenseGap_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmm'))
        $results | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Host "Exported to $path" -ForegroundColor Cyan
    }

    $results
}
