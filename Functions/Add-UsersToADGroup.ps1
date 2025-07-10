function Add-UsersToGroupByDepartment {
    <#
    .SYNOPSIS
        Adds users from specific departments in an OU to an AD group.
    
    .DESCRIPTION
        This function retrieves users from a specified OU, filters them by department,
        and adds them to a target AD group. Only enabled users are processed.
    
    .PARAMETER OU
        The distinguished name of the organizational unit to search in.
    
    .PARAMETER TargetGroup
        The name of the AD group to add users to.
    
    .PARAMETER Departments
        Array of department names to include in the filter.
    
    .PARAMETER WhatIf
        If specified, shows what would be done without making changes.
    
    .PARAMETER Force
        If specified, skips the confirmation prompt.
    
    .EXAMPLE
        Add-UsersToGroupByDepartment -OU "OU=Users,DC=company,DC=com" -TargetGroup "AllStaff" -Departments @("IT","Finance")
    
    .EXAMPLE
        Add-UsersToGroupByDepartment -OU "OU=Users,DC=company,DC=com" -TargetGroup "AllStaff" -Departments @("IT","Finance") -WhatIf
    
    .EXAMPLE
        Add-UsersToGroupByDepartment -OU "OU=Users,DC=company,DC=com" -TargetGroup "AllStaff" -Departments @("IT","Finance") -Force
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OU,
        
        [Parameter(Mandatory = $true)]
        [string]$TargetGroup,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Departments,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    # Import Active Directory module if not already loaded
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to import ActiveDirectory module: $($_.Exception.Message)"
            return
        }
    }

    Write-Host "Starting process to add users to group: $TargetGroup" -ForegroundColor Green
    Write-Host "Target OU: $OU" -ForegroundColor Yellow
    Write-Host "Departments: $($Departments -join ', ')" -ForegroundColor Yellow

    try {
        # Verify the OU exists
        try {
            Get-ADOrganizationalUnit -Identity $OU -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error "OU not found: $OU"
            return
        }

        # Verify the target group exists
        try {
            Get-ADGroup -Identity $TargetGroup -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error "Group not found: $TargetGroup"
            return
        }

        # Get users from the specified OU that belong to the target departments
        $Users = Get-ADUser -Filter * -SearchBase $OU -Properties Department, DisplayName | 
                 Where-Object { $_.Department -in $Departments -and $_.Enabled -eq $true }

        Write-Host "Found $($Users.Count) users matching criteria" -ForegroundColor Cyan

        if ($Users.Count -eq 0) {
            Write-Host "No users found matching the criteria." -ForegroundColor Red
            return
        }

        # Display users that will be processed
        Write-Host "`nUsers to be processed:" -ForegroundColor Yellow
        $Users | ForEach-Object {
            Write-Host "  - $($_.DisplayName) ($($_.SamAccountName)) - Department: $($_.Department)"
        }

        # Confirm before proceeding (unless Force is specified or WhatIf is used)
        if (-not $Force -and -not $WhatIfPreference) {
            $confirmation = Read-Host "`nDo you want to proceed with adding these users to the group? (Y/N)"
            if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
                Write-Host "Operation cancelled by user." -ForegroundColor Yellow
                return
            }
        }

        # Add users to the target group
        $SuccessCount = 0
        $ErrorCount = 0
        $AlreadyMemberCount = 0
        
        foreach ($User in $Users) {
            try {
                if ($PSCmdlet.ShouldProcess($User.DisplayName, "Add to group $TargetGroup")) {
                    # Check if user is already a member
                    $IsMember = Get-ADGroupMember -Identity $TargetGroup -Recursive | 
                               Where-Object { $_.SamAccountName -eq $User.SamAccountName }
                    
                    if ($IsMember) {
                        Write-Host "  User $($User.DisplayName) is already a member of $TargetGroup" -ForegroundColor Yellow
                        $AlreadyMemberCount++
                    } else {
                        Add-ADGroupMember -Identity $TargetGroup -Members $User.SamAccountName
                        Write-Host "  Successfully added $($User.DisplayName) to $TargetGroup" -ForegroundColor Green
                        $SuccessCount++
                    }
                }
            }
            catch {
                Write-Host "  Error processing $($User.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
                $ErrorCount++
            }
        }

        # Summary
        Write-Host "`n--- Summary ---" -ForegroundColor Cyan
        if ($WhatIfPreference) {
            Write-Host "WhatIf mode: $($Users.Count) users would be processed"
        } else {
            Write-Host "Successfully added: $SuccessCount users"
            Write-Host "Already members: $AlreadyMemberCount users"
            Write-Host "Errors encountered: $ErrorCount users"
            Write-Host "Total processed: $($Users.Count) users"
        }
    }
    catch {
        Write-Error "Script error: $($_.Exception.Message)"
        Write-Host "Please check your OU path, group name, and permissions." -ForegroundColor Yellow
    }

    Write-Host "`nOperation completed." -ForegroundColor Green
}

# Optional: Create an alias for shorter usage
New-Alias -Name "Add-DeptUsersToGroup" -Value "Add-UsersToGroupByDepartment" -Force