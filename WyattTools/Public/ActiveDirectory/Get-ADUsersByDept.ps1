<#
.SYNOPSIS
    Searches Active Directory for enabled users by department and exports results to CSV.
.DESCRIPTION
    Queries enabled user accounts in a department and exports Name, JobTitle and Department to a
    CSV file. Wildcards (*) are supported in -Department (for example "5*"). Other LDAP special
    characters (backslash, parentheses, NUL) are escaped. The CSV is always written.
.PARAMETER Department
    Department name or wildcard pattern. Examples: "1234", "5*".
.PARAMETER OutputPath
    CSV file path. Default: <ExportDirectory from config, or current location>\<Department>_Users_<timestamp>.csv
.EXAMPLE
    Get-ADUsersByDept -Department "1234" -OutputPath "C:\Reports\1234_Users.csv"
.EXAMPLE
    Get-ADUsersByDept -Department "5*"
.NOTES
    Name: Get-ADUsersByDept
    Version: 2.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: ActiveDirectory module
#>
function Get-ADUsersByDept {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, HelpMessage = "Enter the department name or wildcard pattern (e.g. 5*)")]
        [ValidateNotNullOrEmpty()]
        [string]$Department,

        [Parameter(Position = 1, HelpMessage = "Enter the output CSV file path")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )

    Assert-Module -Name ActiveDirectory

    if (-not $OutputPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $safeName  = $Department -replace '[\\/:*?"<>|]', '_'
        $OutputPath = Join-Path -Path (Get-ExportDirectory) -ChildPath "${safeName}_Users_${timestamp}.csv"
    }

    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if ($outputDirectory -and -not (Test-Path -Path $outputDirectory)) {
        throw "Output directory does not exist: $outputDirectory"
    }

    # Escape LDAP filter specials per RFC 4515 except '*', which stays a wildcard.
    # Backslash must be replaced first.
    $escaped = $Department.Replace('\', '\5c').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
    $ldapFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(department=$escaped))"

    try {
        Write-Verbose "LDAP filter: $ldapFilter"
        $adUsers = @(Get-ADUser -LDAPFilter $ldapFilter -Properties Department, Title -ErrorAction Stop)
        if ($adUsers.Count -eq 0) {
            Write-Warning "No active users found in department: $Department"
            return
        }

        $results = $adUsers | ForEach-Object {
            [PSCustomObject]@{
                Name       = $_.Name
                JobTitle   = $_.Title
                Department = $_.Department
            }
        } | Sort-Object Department, Name

        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
        Write-Host "Successfully exported $(@($results).Count) user(s) to: $OutputPath" -ForegroundColor Green
        Get-Item -Path $OutputPath
    }
    catch {
        Write-Error "An error occurred while querying Active Directory or exporting data: $_"
    }
}
