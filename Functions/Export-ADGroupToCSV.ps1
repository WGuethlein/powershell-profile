
function Export-ADGroupToCSV {
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
        
        # Check if ActiveDirectory module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Error "ActiveDirectory module is not installed. Please install RSAT tools."
            return
        }

        # Import ActiveDirectory module
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
            # Search for the group
            Write-Verbose "Searching for AD group: $GroupName"
            $adGroups = Get-ADGroup -Filter "Name -like '$GroupName'" -ErrorAction Stop

            # Handle search results
            if ($null -eq $adGroups -or $adGroups.Count -eq 0) {
                Write-Error "No groups found matching pattern: $GroupName"
                return
            }

            # If multiple groups found, let user select
            if ($adGroups -is [array] -and $adGroups.Count -gt 1) {
                Write-Host "`nMultiple groups found matching '$GroupName':" -ForegroundColor Yellow
                for ($i = 0; $i -lt $adGroups.Count; $i++) {
                    Write-Host "  [$i] $($adGroups[$i].Name)" -ForegroundColor Cyan
                }
                
                $selection = Read-Host "`nEnter the number of the group to export (0-$($adGroups.Count - 1))"
                
                if ($selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $adGroups.Count) {
                    $selectedGroup = $adGroups[[int]$selection]
                }
                else {
                    Write-Error "Invalid selection. Export cancelled."
                    return
                }
            }
            else {
                $selectedGroup = $adGroups
            }

            Write-Host "`nProcessing group: $($selectedGroup.Name)" -ForegroundColor Green

            # Set default output path if not specified
            if ([string]::IsNullOrWhiteSpace($OutputPath)) {
                $sanitizedGroupName = $selectedGroup.Name -replace '[\\/:*?"<>|]', '_'
                $OutputPath = "C:\$($sanitizedGroupName)_Members.csv"
            }

            # Validate output directory exists
            $outputDirectory = Split-Path -Path $OutputPath -Parent
            if (-not (Test-Path -Path $outputDirectory)) {
                Write-Error "Output directory does not exist: $outputDirectory"
                return
            }

            # Get group members (direct members only)
            Write-Verbose "Retrieving direct members of group: $($selectedGroup.Name)"
            $groupMembers = Get-ADGroupMember -Identity $selectedGroup.DistinguishedName -ErrorAction Stop

            if ($null -eq $groupMembers -or $groupMembers.Count -eq 0) {
                Write-Warning "Group '$($selectedGroup.Name)' has no direct members."
                return
            }

            Write-Host "Found $($groupMembers.Count) member(s)" -ForegroundColor Cyan

            # Collect user details
            Write-Verbose "Collecting detailed information for each member"
            $memberDetails = @()

            foreach ($member in $groupMembers) {
                # Only process user objects (skip computer accounts and nested groups)
                if ($member.objectClass -eq 'user') {
                    try {
                        # Get detailed user information
                        $userDetails = Get-ADUser -Identity $member.DistinguishedName `
                            -Properties DisplayName, EmailAddress, Department, Enabled `
                            -ErrorAction Stop

                        # Create custom object for CSV export
                        $memberDetails += [PSCustomObject]@{
                            Name       = $userDetails.DisplayName
                            Email      = $userDetails.EmailAddress
                            Department = $userDetails.Department
                            Status     = if ($userDetails.Enabled) { "Enabled" } else { "Disabled" }
                        }

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

            # Check if any users were processed
            if ($memberDetails.Count -eq 0) {
                Write-Warning "No user accounts found in group '$($selectedGroup.Name)'. Group may only contain computer accounts or nested groups."
                return
            }

            # Display members on screen
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "Group Members: $($selectedGroup.Name)" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            $memberDetails | Format-Table -AutoSize
            
            # Export to CSV
            if ($PSCmdlet.ShouldProcess($OutputPath, "Export group members to CSV")) {
                $memberDetails | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                Write-Host "`nSuccessfully exported $($memberDetails.Count) user(s) to: $OutputPath" -ForegroundColor Green
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