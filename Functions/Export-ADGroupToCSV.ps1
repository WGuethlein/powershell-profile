function Export-ADGroupToCSV {
    <#
    .SYNOPSIS
        Exports AD group members to a CSV file.

    .DESCRIPTION
        Searches for AD groups by name or wildcard pattern, prompts the user to select a single group
        or export all matched groups at once. When exporting all groups, members are combined into a
        single CSV with a GroupName column prepended to each row.

    .PARAMETER GroupName
        The AD group name or wildcard search pattern (e.g. "IT-*").

    .PARAMETER OutputPath
        Full file path for the output CSV. When exporting a single group and omitted, defaults to
        C:\<GroupName>_Members.csv. When exporting all groups and omitted, defaults to
        C:\<SearchPattern>_AllGroups_Members.csv. When exporting all groups and provided, used
        directly as the combined CSV file path.

    .EXAMPLE
        Export-ADGroupToCSV -GroupName "IT-*"
        # Prompts to select one group, or enter A to export all matched groups.

    .EXAMPLE
        Export-ADGroupToCSV -GroupName "IT-*" -OutputPath "C:\Exports\combined.csv"
        # If A is selected, writes the combined CSV to the specified path.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            HelpMessage = "Enter the AD group name or search pattern (supports wildcards)"
        )]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            HelpMessage = "Enter the full path for the output CSV file"
        )]
        [string]$OutputPath
    )

    begin {
        Write-Verbose "Starting Export-ADGroupToCSV function"

        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Error "ActiveDirectory module is not installed. Please install RSAT tools."
            return
        }

        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-Verbose "ActiveDirectory module imported successfully"
        }
        catch {
            Write-Error "Failed to import ActiveDirectory module: $_"
            return
        }
    }

    process {
        try {
            # Search for matching groups
            Write-Verbose "Searching for AD group: $GroupName"
            $adGroups = Get-ADGroup -Filter "Name -like '$GroupName'" -ErrorAction Stop

            if ($null -eq $adGroups -or $adGroups.Count -eq 0) {
                Write-Error "No groups found matching pattern: $GroupName"
                return
            }

            # Normalize to array for consistent handling
            $adGroupsArray = @($adGroups)

            # Determine which groups to process
            $groupsToExport = @()
            $exportAll = $false

            if ($adGroupsArray.Count -gt 1) {
                Write-Host "`nMultiple groups found matching '$GroupName':" -ForegroundColor Yellow
                for ($i = 0; $i -lt $adGroupsArray.Count; $i++) {
                    Write-Host "  [$i] $($adGroupsArray[$i].Name)" -ForegroundColor Cyan
                }
                Write-Host "  [A] Export all groups into a single combined CSV" -ForegroundColor Magenta

                $selection = Read-Host "`nEnter a number (0-$($adGroupsArray.Count - 1)) or A to export all"

                if ($selection -match '^[Aa](ll)?$') {
                    $groupsToExport = $adGroupsArray
                    $exportAll = $true
                }
                elseif ($selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $adGroupsArray.Count) {
                    $groupsToExport = @($adGroupsArray[[int]$selection])
                }
                else {
                    Write-Error "Invalid selection. Export cancelled."
                    return
                }
            }
            else {
                $groupsToExport = $adGroupsArray
            }

            # Resolve output path
            if ($exportAll) {
                if ([string]::IsNullOrWhiteSpace($OutputPath)) {
                    $sanitizedPattern = $GroupName -replace '[\\/:*?"<>|]', '_'
                    $OutputPath = "C:\$($sanitizedPattern)_AllGroups_Members.csv"
                }
                # When exporting all, OutputPath is always treated as the file path directly
            }

            # Validate output directory
            $outputDirectory = Split-Path -Path $OutputPath -Parent
            if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
                Write-Error "Output directory does not exist: $outputDirectory"
                return
            }

            # Collect members from all target groups
            $allMemberDetails = @()

            foreach ($group in $groupsToExport) {
                Write-Host "`nProcessing group: $($group.Name)" -ForegroundColor Green

                # Set per-group output path for single-group exports
                $resolvedOutputPath = $OutputPath
                if (-not $exportAll -and [string]::IsNullOrWhiteSpace($OutputPath)) {
                    $sanitizedGroupName = $group.Name -replace '[\\/:*?"<>|]', '_'
                    $resolvedOutputPath = "C:\$($sanitizedGroupName)_Members.csv"
                }

                Write-Verbose "Retrieving direct members of group: $($group.Name)"
                $groupMembers = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop

                if ($null -eq $groupMembers -or $groupMembers.Count -eq 0) {
                    Write-Warning "Group '$($group.Name)' has no direct members. Skipping."
                    continue
                }

                Write-Host "Found $($groupMembers.Count) member(s)" -ForegroundColor Cyan

                $memberDetails = @()

                foreach ($member in $groupMembers) {
                    if ($member.objectClass -eq 'user') {
                        try {
                            $userDetails = Get-ADUser -Identity $member.DistinguishedName `
                                -Properties DisplayName, EmailAddress, Department, Enabled `
                                -ErrorAction Stop

                            $record = [PSCustomObject]@{
                                GroupName  = $group.Name
                                Name       = $userDetails.DisplayName
                                Email      = $userDetails.EmailAddress
                                Department = $userDetails.Department
                                Status     = if ($userDetails.Enabled) { "Enabled" } else { "Disabled" }
                            }

                            $memberDetails += $record
                            Write-Verbose "Processed user: $($userDetails.DisplayName)"
                        }
                        catch {
                            Write-Warning "Failed to retrieve details for user: $($member.Name) - $_"
                        }
                    }
                    else {
                        Write-Verbose "Skipping non-user object: $($member.Name) (Type: $($member.objectClass))"
                    }
                }

                if ($memberDetails.Count -eq 0) {
                    Write-Warning "No user accounts found in group '$($group.Name)'. Group may only contain computer accounts or nested groups."
                    continue
                }

                # Display group members on screen
                Write-Host "`n========================================" -ForegroundColor Cyan
                Write-Host "Group Members: $($group.Name)" -ForegroundColor Cyan
                Write-Host "========================================" -ForegroundColor Cyan
                $memberDetails | Format-Table -AutoSize

                if ($exportAll) {
                    # Accumulate for combined export
                    $allMemberDetails += $memberDetails
                }
                else {
                    # Export single group immediately
                    if ($PSCmdlet.ShouldProcess($resolvedOutputPath, "Export group members to CSV")) {
                        $memberDetails | Export-Csv -Path $resolvedOutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                        Write-Host "`nSuccessfully exported $($memberDetails.Count) user(s) to: $resolvedOutputPath" -ForegroundColor Green
                    }
                }
            }

            # Write the combined CSV for export-all
            if ($exportAll) {
                if ($allMemberDetails.Count -eq 0) {
                    Write-Warning "No user accounts were found across any of the matched groups. Nothing exported."
                    return
                }

                if ($PSCmdlet.ShouldProcess($OutputPath, "Export all group members to combined CSV")) {
                    $allMemberDetails | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                    Write-Host "`n========================================" -ForegroundColor Magenta
                    Write-Host "Combined export complete" -ForegroundColor Magenta
                    Write-Host "  Groups  : $($groupsToExport.Count)" -ForegroundColor Magenta
                    Write-Host "  Users   : $($allMemberDetails.Count)" -ForegroundColor Magenta
                    Write-Host "  Output  : $OutputPath" -ForegroundColor Magenta
                    Write-Host "========================================" -ForegroundColor Magenta
                }
            }
        }
        catch {
            Write-Error "An error occurred during export: $_"
            Write-Error $_.Exception.StackTrace
        }
    }

    end {
        Write-Verbose "Export-ADGroupToCSV function completed"
    }
}