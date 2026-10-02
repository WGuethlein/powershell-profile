<#
.SYNOPSIS
    Gets AD department info for users listed in a file or a single user.
.DESCRIPTION
    Resolves each identifier (email, UPN, or SamAccountName) and returns Email, DisplayName and
    Department. Unresolved users are reported as <NOT FOUND>.
.PARAMETER File
    Path to a text/CSV file with one identifier per line (header row and blank lines are skipped).
.PARAMETER User
    Single email, UPN, or SamAccountName.
.EXAMPLE
    Get-ADUserDepartment -File "C:\users.csv"
.EXAMPLE
    Get-ADUserDepartment -User "jdoe@contoso.com"
.NOTES
    Name: Get-ADUserDepartment
    Version: 2.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: ActiveDirectory module
#>
function Get-ADUserDepartment {
    [CmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$File,

        [Parameter(Mandatory, ParameterSetName = 'SingleUser')]
        [ValidateNotNullOrEmpty()]
        [string]$User
    )

    Assert-Module -Name ActiveDirectory

    $props = 'Department', 'EmailAddress', 'DisplayName'
    if ($PSCmdlet.ParameterSetName -eq 'File') {
        $resolved = @(Resolve-ADUserIdentity -File $File -Properties $props)
        Write-Host "Processing $($resolved.Count) users from '$File'" -ForegroundColor Cyan
    }
    else {
        $resolved = @(Resolve-ADUserIdentity -User $User -Properties $props)
    }

    $results = New-Object 'System.Collections.Generic.List[PSCustomObject]'
    $notFoundCount = 0
    foreach ($item in $resolved) {
        if ($null -eq $item.ADUser) {
            Write-Warning "User not found: $($item.Input) ($($item.Error))"
            $notFoundCount++
            $results.Add([PSCustomObject]@{ Email = $item.Input; DisplayName = $null; Department = '<NOT FOUND>' })
            continue
        }
        $u = $item.ADUser
        $email = $item.Input
        if ($u.EmailAddress) { $email = $u.EmailAddress }
        $dept = '<none>'
        if ($u.Department) { $dept = $u.Department }
        $results.Add([PSCustomObject]@{ Email = $email; DisplayName = $u.DisplayName; Department = $dept })
    }

    Write-Host ""
    $results | Format-Table -AutoSize | Out-Host
    Write-Host "========== Summary ==========" -ForegroundColor Cyan
    Write-Host "Total processed: $($results.Count)" -ForegroundColor Green
    Write-Host "Not found in AD: $notFoundCount" -ForegroundColor Yellow

    # Also return the objects so they can be piped/exported.
    $results
}
