<#
.SYNOPSIS
    Searches Active Directory for enabled users by department.
.DESCRIPTION
    Queries enabled user accounts in a department and returns Name, JobTitle and Department
    objects. Wildcards (*) are supported in -Department (for example "5*"). Other LDAP special
    characters (backslash, parentheses, NUL) are escaped. With -Export the rows are also written
    to a CSV.
.PARAMETER Department
    Department name or wildcard pattern. Examples: "1234", "5*".
.PARAMETER Export
    Write results to <Department>_Users_yyyyMMdd_HHmm.csv in the configured export directory.
.EXAMPLE
    Get-ADUsersByDept -Department "1234" -Export
.EXAMPLE
    Get-ADUsersByDept -Department "5*" | Format-Table
.EXAMPLE
    Get-ADUsersByDept "5*" | Group-Object Department | Sort-Object Count -Descending
    Counts enabled users per department across a wildcard range (department is positional).
.EXAMPLE
    Get-ADUsersByDept -Department "12*" -Export | Where-Object JobTitle -like '*Manager*'
    Saves the full list to CSV and also filters the on-screen output to managers.
.NOTES
    Name: Get-ADUsersByDept
    Version: 2.1.0
    Author: WGuethlein
    Date: 2026-10-04
    Prerequisites: ActiveDirectory module
#>
function Get-ADUsersByDept {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, HelpMessage = "Enter the department name or wildcard pattern (e.g. 5*)")]
        [ValidateNotNullOrEmpty()]
        [string]$Department,

        [Parameter()]
        [switch]$Export
    )

    Assert-Module -Name ActiveDirectory

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

        if ($Export) {
            $safeName = $Department -replace '[\\/:*?"<>|]', '_'
            $path = Join-Path (Get-ExportDirectory) ('{0}_Users_{1}.csv' -f $safeName, (Get-Date -Format 'yyyyMMdd_HHmm'))
            $results | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
            Write-Host "Exported to $path" -ForegroundColor Cyan
        }

        $results
    }
    catch {
        Write-Error "An error occurred while querying Active Directory or exporting data: $_"
    }
}
