<#
.SYNOPSIS
    Searches Active Directory for active users by department and exports results to CSV.

.DESCRIPTION
    This function queries Active Directory for all enabled user accounts in a specified
    department and exports their names and job titles to a CSV file. Wildcards (*) are
    supported in the Department parameter to match multiple departments at once (e.g.,
    "5*" will match 5001, 5210, 5432, etc.).

.PARAMETER Department
    The name of the department to search for (case-insensitive). Supports wildcards (*).
    Examples: "1234" for exact match, "5*" for all departments starting with 5.

.PARAMETER OutputPath
    The file path where the CSV will be saved. If not specified, saves to the current
    directory with filename format: Department_Users_YYYYMMDD_HHMMSS.csv

.EXAMPLE
    Get-ADUsersByDept -Department "1234" -OutputPath "C:\Reports\1234_Users.csv"
    Exports all active users in department 1234 to the specified file path.

.EXAMPLE
    Get-ADUsersByDept -Department "5*"
    Exports all active users in any department beginning with 5.

.NOTES
    Name:         Get-ADUsersByDepartment.ps1
    Version:      1.1
    Author:       WGuethlein
    Date:         2026-02-23

#>

function Get-ADUsersByDept {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Enter the department name or wildcard pattern (e.g. 5*)")]
        [ValidateNotNullOrEmpty()]
        [string]$Department,

        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Enter the output CSV file path")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )

    begin {
        Write-Verbose "Starting Get-ADUsersByDepartment function"
        
        # Check if ActiveDirectory module is available
        try {
            if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
                throw "Active Directory PowerShell module is not installed. Please install RSAT tools."
            }
            
            # Import the module if not already loaded
            if (-not (Get-Module -Name ActiveDirectory)) {
                Write-Verbose "Importing Active Directory module..."
                Import-Module ActiveDirectory -ErrorAction Stop
            }
        }
        catch {
            Write-Error "Failed to load Active Directory module: $_"
            return
        }

        # Set default output path if not specified
        if (-not $OutputPath) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $sanitizedDepartment = $Department -replace '[\\/:*?"<>|]', '_'
            $OutputPath = Join-Path -Path (Get-Location) -ChildPath "${sanitizedDepartment}_Users_${timestamp}.csv"
        }

        # Validate output directory exists
        $outputDirectory = Split-Path -Path $OutputPath -Parent
        if ($outputDirectory -and -not (Test-Path -Path $outputDirectory)) {
            Write-Error "Output directory does not exist: $outputDirectory"
            return
        }

        Write-Verbose "Output will be saved to: $OutputPath"
    }

    process {
        try {
            Write-Verbose "Searching for active users in department: $Department"

            # LDAP filter supports wildcards natively; use it for all queries so that
            # both exact matches ("1234") and wildcard patterns ("5*") work identically.
            # PowerShell's -Filter parameter does not support wildcards with -eq, so
            # we build an LDAP filter string instead.
            $ldapFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(department=$Department))"

            $adUsers = Get-ADUser -LDAPFilter $ldapFilter -Properties Department, Title -ErrorAction Stop

            # Check if any users were found
            if ($null -eq $adUsers -or @($adUsers).Count -eq 0) {
                Write-Warning "No active users found in department: $Department"
                return
            }

            Write-Verbose "Found $(@($adUsers).Count) active user(s)"

            # Create custom objects with Name and Job Title
            $results = $adUsers | ForEach-Object {
                [PSCustomObject]@{
                    Name       = $_.Name
                    JobTitle   = $_.Title
                    Department = $_.Department
                }
            } | Sort-Object Department, Name

            # Export to CSV with WhatIf support
            if ($PSCmdlet.ShouldProcess($OutputPath, "Export $($results.Count) user(s) to CSV")) {
                $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
                Write-Host "Successfully exported $($results.Count) user(s) to: $OutputPath" -ForegroundColor Green
                
                # Return the file path for pipeline usage
                Get-Item -Path $OutputPath
            }
        }
        catch {
            Write-Error "An error occurred while querying Active Directory or exporting data: $_"
        }
    }

    end {
        Write-Verbose "Get-ADUsersByDepartment function completed"
    }
}