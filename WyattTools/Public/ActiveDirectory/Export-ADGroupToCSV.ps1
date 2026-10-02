<#
.SYNOPSIS
    Exports AD group members to a CSV file.
.DESCRIPTION
    Searches for AD groups by name or wildcard pattern and prompts to select a single group or
    export all matched groups. When exporting all groups, members are combined into one CSV with
    a GroupName column. Only direct user members are exported.
.PARAMETER GroupName
    The AD group name or wildcard search pattern (for example "IT-*"). Accepts pipeline input.
.PARAMETER OutputPath
    Full file path for the output CSV. When omitted, defaults to the current location:
    <GroupName>_Members.csv for one group, or <SearchPattern>_AllGroups_Members.csv for all.
.EXAMPLE
    Export-ADGroupToCSV -GroupName "IT-*"
    Prompts to select one group, or enter A to export all matched groups.
.EXAMPLE
    Export-ADGroupToCSV -GroupName "IT-*" -OutputPath "C:\Exports\combined.csv"
    If A is selected, writes the combined CSV to the specified path.
.NOTES
    Name: Export-ADGroupToCSV
    Version: 2.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: ActiveDirectory module
#>
function Export-ADGroupToCSV {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, HelpMessage = "Enter the AD group name or search pattern (supports wildcards)")]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName,

        [Parameter(Position = 1, HelpMessage = "Enter the full path for the output CSV file")]
        [string]$OutputPath
    )

    begin {
        Assert-Module -Name ActiveDirectory
    }

    process {
        try {
            $safeFilter = $GroupName.Replace("'", "''")
            $adGroups = @(Get-ADGroup -Filter "Name -like '$safeFilter'" -ErrorAction Stop)

            if ($adGroups.Count -eq 0) {
                Write-Error "No groups found matching pattern: $GroupName"
                return
            }

            $groupsToExport = $adGroups
            $exportAll = $false

            if ($adGroups.Count -gt 1) {
                Write-Host "`nMultiple groups found matching '$GroupName':" -ForegroundColor Yellow
                for ($i = 0; $i -lt $adGroups.Count; $i++) {
                    Write-Host "  [$i] $($adGroups[$i].Name)" -ForegroundColor Cyan
                }
                Write-Host "  [A] Export all groups into a single combined CSV" -ForegroundColor Magenta

                $selection = Read-Host "`nEnter a number (0-$($adGroups.Count - 1)) or A to export all"

                if ($selection -match '^[Aa](ll)?$') {
                    $exportAll = $true
                }
                elseif ($selection -match '^\d+$' -and [int]$selection -lt $adGroups.Count) {
                    $groupsToExport = @($adGroups[[int]$selection])
                }
                else {
                    Write-Error "Invalid selection. Export cancelled."
                    return
                }
            }

            # Local copy so pipeline items do not inherit each other's path.
            $targetPath = $OutputPath
            $cwd = (Get-Location).Path

            if ($exportAll -and [string]::IsNullOrWhiteSpace($targetPath)) {
                $safePattern = $GroupName -replace '[\\/:*?"<>|]', '_'
                $targetPath = Join-Path $cwd "${safePattern}_AllGroups_Members.csv"
            }

            if (-not [string]::IsNullOrWhiteSpace($targetPath)) {
                $outputDirectory = Split-Path -Path $targetPath -Parent
                if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
                    Write-Error "Output directory does not exist: $outputDirectory"
                    return
                }
            }

            $allMemberDetails = New-Object 'System.Collections.Generic.List[PSCustomObject]'

            foreach ($group in $groupsToExport) {
                Write-Host "`nProcessing group: $($group.Name)" -ForegroundColor Green

                $groupPath = $targetPath
                if (-not $exportAll -and [string]::IsNullOrWhiteSpace($groupPath)) {
                    $safeGroup = $group.Name -replace '[\\/:*?"<>|]', '_'
                    $groupPath = Join-Path $cwd "${safeGroup}_Members.csv"
                }

                $groupMembers = @(Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop)
                if ($groupMembers.Count -eq 0) {
                    Write-Warning "Group '$($group.Name)' has no direct members. Skipping."
                    continue
                }
                Write-Host "Found $($groupMembers.Count) member(s)" -ForegroundColor Cyan

                $memberDetails = New-Object 'System.Collections.Generic.List[PSCustomObject]'
                foreach ($member in $groupMembers) {
                    if ($member.objectClass -ne 'user') {
                        Write-Verbose "Skipping non-user object: $($member.Name) (Type: $($member.objectClass))"
                        continue
                    }
                    try {
                        $userDetails = Get-ADUser -Identity $member.DistinguishedName `
                            -Properties DisplayName, EmailAddress, Department, Enabled -ErrorAction Stop
                        $status = 'Disabled'
                        if ($userDetails.Enabled) { $status = 'Enabled' }
                        $memberDetails.Add([PSCustomObject]@{
                            GroupName  = $group.Name
                            Name       = $userDetails.DisplayName
                            Email      = $userDetails.EmailAddress
                            Department = $userDetails.Department
                            Status     = $status
                        })
                    }
                    catch {
                        Write-Warning "Failed to retrieve details for user: $($member.Name) - $_"
                    }
                }

                if ($memberDetails.Count -eq 0) {
                    Write-Warning "No user accounts found in group '$($group.Name)'. Group may only contain computer accounts or nested groups."
                    continue
                }

                Write-Host "`n========================================" -ForegroundColor Cyan
                Write-Host "Group Members: $($group.Name)" -ForegroundColor Cyan
                Write-Host "========================================" -ForegroundColor Cyan
                $memberDetails | Format-Table -AutoSize | Out-Host

                if ($exportAll) {
                    $allMemberDetails.AddRange($memberDetails)
                }
                elseif ($PSCmdlet.ShouldProcess($groupPath, "Export group members to CSV")) {
                    $memberDetails | Export-Csv -Path $groupPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                    Write-Host "`nSuccessfully exported $($memberDetails.Count) user(s) to: $groupPath" -ForegroundColor Green
                }
            }

            if ($exportAll) {
                if ($allMemberDetails.Count -eq 0) {
                    Write-Warning "No user accounts were found across any of the matched groups. Nothing exported."
                    return
                }
                if ($PSCmdlet.ShouldProcess($targetPath, "Export all group members to combined CSV")) {
                    $allMemberDetails | Export-Csv -Path $targetPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                    Write-Host "`n========================================" -ForegroundColor Magenta
                    Write-Host "Combined export complete" -ForegroundColor Magenta
                    Write-Host "  Groups  : $($groupsToExport.Count)" -ForegroundColor Magenta
                    Write-Host "  Users   : $($allMemberDetails.Count)" -ForegroundColor Magenta
                    Write-Host "  Output  : $targetPath" -ForegroundColor Magenta
                    Write-Host "========================================" -ForegroundColor Magenta
                }
            }
        }
        catch {
            Write-Error "An error occurred during export: $_"
        }
    }
}
