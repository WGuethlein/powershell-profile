<#
.SYNOPSIS
    Add AD group membership to users listed in CSV file or single user
.DESCRIPTION
    Reads email addresses from CSV or processes single user and adds specified AD group to each user
.PARAMETER File
    Path to CSV file containing email addresses
.PARAMETER User
    Single email address or SamAccountName to process
.PARAMETER Group
    Name or DistinguishedName of AD group to add
.EXAMPLE
    Add-ADGroupToUsers -File "C:\users.csv" -Group "Sales Team"
.EXAMPLE
    Add-ADGroupToUsers -User "jdoe@dlz.com" -Group "Sales Team"
.EXAMPLE
    Add-ADGroupToUsers -User "jdoe" -Group "Sales Team"
.NOTES
    Name: Add-ADGroupToUsers
    Author: WGuethlein
    Date: 2026-01-02
    Prerequisites: ActiveDirectory module, appropriate AD permissions
#>
function Add-ADGroup {
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
        $transcriptPath = "$env:TEMP\Add-ADGroupToUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Start-Transcript -Path $transcriptPath
        
        $successCount = 0
        $failCount = 0
        $notFoundCount = 0
        $alreadyMemberCount = 0
    }
    
    process {
        try {
            # Determine user list based on parameter set
            if ($PSCmdlet.ParameterSetName -eq 'File') {
                # Read CSV - handles single column with or without header
                $csvContent = Import-Csv -Path $File -ErrorAction Stop
                $userList = $csvContent.PSObject.Properties.Value
                Write-Host "Processing $($userList.Count) users from '$File'" -ForegroundColor Cyan
            }
            else {
                # Single user
                $userList = @($User)
                Write-Host "Processing single user: $User" -ForegroundColor Cyan
            }
            
            Write-Host "Adding to group: $($adGroup.Name)" -ForegroundColor Cyan
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
                    
                    # Check if user is already a member
                    $isMember = Get-ADGroupMember -Identity $adGroup -Recursive | 
                                Where-Object { $_.SamAccountName -eq $adUser.SamAccountName }
                    
                    if ($null -ne $isMember) {
                        Write-Verbose "User already in group (skipping): $userIdentifier ($($adUser.SamAccountName))"
                        $alreadyMemberCount++
                        continue
                    }
                    
                    # Add to group
                    if ($PSCmdlet.ShouldProcess("$userIdentifier ($($adUser.SamAccountName))", "Add to $($adGroup.Name)")) {
                        Add-ADGroupMember -Identity $adGroup -Members $adUser -ErrorAction Stop
                        Write-Host "Added: $userIdentifier ($($adUser.SamAccountName))" -ForegroundColor Green
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
        Write-Host "Successfully added: $successCount" -ForegroundColor Green
        Write-Host "Failed: $failCount" -ForegroundColor Red
        Write-Host "Not found in AD: $notFoundCount" -ForegroundColor Yellow
        Write-Host "Already members: $alreadyMemberCount" -ForegroundColor Gray
        Write-Host "Transcript: $transcriptPath" -ForegroundColor Cyan
        
        Stop-Transcript
    }
}