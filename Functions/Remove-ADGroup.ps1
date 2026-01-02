<#
.SYNOPSIS
    Remove AD group membership from users listed in CSV file or single user
.DESCRIPTION
    Reads email addresses from CSV or processes single user and removes specified AD group from each user
.PARAMETER File
    Path to CSV file containing email addresses
.PARAMETER User
    Single email address or SamAccountName to process
.PARAMETER Group
    Name or DistinguishedName of AD group to remove
.EXAMPLE
    Remove-ADGroupFromUsers -File "C:\users.csv" -Group "Sales Team"
.EXAMPLE
    Remove-ADGroupFromUsers -User "jdoe@dlz.com" -Group "Sales Team"
.EXAMPLE
    Remove-ADGroupFromUsers -User "jdoe" -Group "Sales Team"
.NOTES
    Name: Remove-ADGroupFromUsers
    Author: WGuethlein
    Date: 2026-01-02
    Prerequisites: ActiveDirectory module, appropriate AD permissions
#>
function Remove-ADGroup {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$File,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'SingleUser')]
        [ValidateNotNullOrEmpty()]
        [string]$User,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Group
    )
    
    begin {
        # Verify ActiveDirectory module
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "ActiveDirectory module not found. Install RSAT tools."
        }
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # Verify group exists
        try {
            $adGroup = Get-ADGroup -Identity $Group -ErrorAction Stop
            Write-Verbose "Target group: $($adGroup.Name) ($($adGroup.DistinguishedName))"
        }
        catch {
            throw "AD group '$Group' not found: $_"
        }
        
        # Start transcript
        $transcriptPath = "$env:TEMP\Remove-ADGroupFromUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Start-Transcript -Path $transcriptPath
        
        $successCount = 0
        $failCount = 0
        $notFoundCount = 0
    }
    
    process {
        try {
            # Determine user list based on parameter set
            if ($PSCmdlet.ParameterSetName -eq 'File') {
                # Read CSV - handles single column with or without header
                $userList = Get-Content -Path $File -ErrorAction Stop | Where-Object { $_ -ne $null -and $_ -ne '' }
                Write-Host "Processing $($userList.Count) users from '$File'" -ForegroundColor Cyan
            }
            else {
                # Single user
                $userList = @($User)
                Write-Host "Processing single user: $User" -ForegroundColor Cyan
            }
            
            Write-Host "Removing group: $($adGroup.Name)" -ForegroundColor Cyan
            Write-Host ""
            
            foreach ($userIdentifier in $userList) {
                $userIdentifier = $userIdentifier.Trim()
                if ([string]::IsNullOrWhiteSpace($userIdentifier)) { continue }
                
                try {
                    # Find user by email or SamAccountName
                    $adUser = $null
                    if ($userIdentifier -like "*@*") {
                        $adUser = Get-ADUser -Filter "EmailAddress -eq '$userIdentifier'" -ErrorAction Stop
                    }
                    else {
                        $adUser = Get-ADUser -Identity $userIdentifier -ErrorAction Stop
                    }
                    
                    if ($null -eq $adUser) {
                        Write-Warning "User not found: $userIdentifier"
                        $notFoundCount++
                        continue
                    }
                    
                    # Check if user is member
                    $isMember = Get-ADGroupMember -Identity $adGroup -Recursive | 
                                Where-Object { $_.SamAccountName -eq $adUser.SamAccountName }
                    
                    if ($null -eq $isMember) {
                        Write-Verbose "User not in group (skipping): $userIdentifier ($($adUser.SamAccountName))"
                        continue
                    }
                    
                    # Remove from group
                    if ($PSCmdlet.ShouldProcess("$userIdentifier ($($adUser.SamAccountName))", "Remove from $($adGroup.Name)")) {
                        Remove-ADGroupMember -Identity $adGroup -Members $adUser -Confirm:$false -ErrorAction Stop
                        Write-Host "Removed: $userIdentifier ($($adUser.SamAccountName))" -ForegroundColor Green
                        $successCount++
                    }
                }
                catch {
                    Write-Error "Failed to process $userIdentifier : $_"
                    $failCount++
                }
            }
        }
        catch {
            Write-Error "Failed to process input: $_"
            throw
        }
    }
    
    end {
        Write-Host ""
        Write-Host "========== Summary ==========" -ForegroundColor Cyan
        Write-Host "Successfully removed: $successCount" -ForegroundColor Green
        Write-Host "Failed: $failCount" -ForegroundColor Red
        Write-Host "Not found in AD: $notFoundCount" -ForegroundColor Yellow
        Write-Host "Transcript: $transcriptPath" -ForegroundColor Cyan
        
        Stop-Transcript
    }
}