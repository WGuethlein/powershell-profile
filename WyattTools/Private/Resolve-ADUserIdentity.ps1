<#
.SYNOPSIS
    Resolves user identifiers (email, UPN, SamAccountName) to AD user objects.
.DESCRIPTION
    Takes one or more identifiers via -User, or a text/CSV file via -File (one identifier per
    line; blank lines and header rows such as Email/UserPrincipalName are skipped). Identifiers
    containing '@' are looked up by EmailAddress, then UserPrincipalName; anything else is
    looked up by Get-ADUser -Identity. Emits one object per identifier: Input, ADUser, Error.
.PARAMETER User
    One or more identifiers.
.PARAMETER File
    Path to a file containing identifiers, one per line.
.PARAMETER Properties
    Extra AD properties to request on the returned user objects.
.EXAMPLE
    Resolve-ADUserIdentity -User 'jdoe@contoso.com' -Properties Department
.NOTES
    Name: Resolve-ADUserIdentity
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: ActiveDirectory module
#>
function Resolve-ADUserIdentity {
    [CmdletBinding(DefaultParameterSetName = 'User')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'User')]
        [string[]]$User,

        [Parameter(Mandatory, ParameterSetName = 'File')]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$File,

        [string[]]$Properties = @()
    )

    $headerNames = 'Email', 'EmailAddress', 'User', 'UserPrincipalName', 'SamAccountName'

    # Only pass -Properties when requested (empty array is not worth the risk).
    $propArgs = @{}
    if ($Properties.Count -gt 0) { $propArgs['Properties'] = $Properties }

    if ($PSCmdlet.ParameterSetName -eq 'File') {
        $raw = Get-Content -LiteralPath $File -ErrorAction Stop
    }
    else {
        $raw = $User
    }

    foreach ($line in $raw) {
        if ($null -eq $line) { continue }
        $id = $line.Trim()
        if ($id -eq '') { continue }
        if ($PSCmdlet.ParameterSetName -eq 'File' -and $headerNames -contains $id) { continue }

        $adUser = $null
        $err    = $null
        try {
            if ($id.Contains('@')) {
                $safe   = $id.Replace("'", "''")
                $found  = @(Get-ADUser -Filter "EmailAddress -eq '$safe'" @propArgs -ErrorAction Stop)
                if ($found.Count -eq 0) {
                    $found = @(Get-ADUser -Filter "UserPrincipalName -eq '$safe'" @propArgs -ErrorAction Stop)
                }
                if ($found.Count -eq 1) { $adUser = $found[0] }
                elseif ($found.Count -gt 1) { $err = "Multiple users match '$id'." }
                else { $err = "User not found: $id" }
            }
            else {
                $adUser = Get-ADUser -Identity $id @propArgs -ErrorAction Stop
            }
        }
        catch {
            $err = $_.Exception.Message
        }

        [PSCustomObject]@{
            Input  = $id
            ADUser = $adUser
            Error  = $err
        }
    }
}
