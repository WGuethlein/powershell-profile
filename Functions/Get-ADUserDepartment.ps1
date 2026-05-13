<#
.SYNOPSIS
    Get AD department info for users listed in CSV file or single user
.DESCRIPTION
    Reads email addresses from CSV or processes single user and looks up their department from AD
.PARAMETER File
    Path to CSV file containing email addresses
.PARAMETER User
    Single email address or SamAccountName to process
.EXAMPLE
    Get-ADUserDepartment -File "C:\users.csv"
.EXAMPLE
    Get-ADUserDepartment -User "jdoe@dlz.com"
.NOTES
    Name: Get-ADUserDepartment
    Author: WGuethlein
    Date: 2026-05-13
    Prerequisites: ActiveDirectory module
#>
function Get-ADUserDepartment {
    [CmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$File,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'SingleUser')]
        [ValidateNotNullOrEmpty()]
        [string]$User
    )
    
    begin {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "ActiveDirectory module not found. Install RSAT tools."
        }
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        $notFoundCount = 0
        $failCount = 0
    }
    
    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'File') {
                $userList = Get-Content -Path $File -ErrorAction Stop | Where-Object { $_ -ne $null -and $_ -ne '' }
                Write-Host "Processing $($userList.Count) users from '$File'" -ForegroundColor Cyan
            }
            else {
                $userList = @($User)
                Write-Host "Processing single user: $User" -ForegroundColor Cyan
            }
            Write-Host ""
            
            foreach ($userIdentifier in $userList) {
                $userIdentifier = $userIdentifier.Trim()
                if ([string]::IsNullOrWhiteSpace($userIdentifier)) { continue }
                
                # Skip a header row if present
                if ($userIdentifier -ieq 'Email' -or $userIdentifier -ieq 'EmailAddress') { continue }
                
                try {
                    $adUser = $null
                    if ($userIdentifier -like "*@*") {
                        $adUser = Get-ADUser -Filter "EmailAddress -eq '$userIdentifier'" -Properties Department, EmailAddress, DisplayName -ErrorAction Stop
                    }
                    else {
                        $adUser = Get-ADUser -Identity $userIdentifier -Properties Department, EmailAddress, DisplayName -ErrorAction Stop
                    }
                    
                    if ($null -eq $adUser) {
                        Write-Warning "User not found: $userIdentifier"
                        $results.Add([PSCustomObject]@{
                            Email      = $userIdentifier
                            DisplayName = $null
                            Department = '<NOT FOUND>'
                        })
                        $notFoundCount++
                        continue
                    }
                    
                    $results.Add([PSCustomObject]@{
                        Email       = if ($adUser.EmailAddress) { $adUser.EmailAddress } else { $userIdentifier }
                        DisplayName = $adUser.DisplayName
                        Department  = if ($adUser.Department) { $adUser.Department } else { '<none>' }
                    })
                }
                catch {
                    Write-Error "Failed to process $userIdentifier : $_"
                    $results.Add([PSCustomObject]@{
                        Email      = $userIdentifier
                        DisplayName = $null
                        Department = '<ERROR>'
                    })
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
        $results | Format-Table -AutoSize
        
        Write-Host "========== Summary ==========" -ForegroundColor Cyan
        Write-Host "Total processed: $($results.Count)" -ForegroundColor Green
        Write-Host "Not found in AD: $notFoundCount" -ForegroundColor Yellow
        Write-Host "Failed: $failCount" -ForegroundColor Red
        
        # Also return the objects so they can be piped/exported
        return $results
    }
}