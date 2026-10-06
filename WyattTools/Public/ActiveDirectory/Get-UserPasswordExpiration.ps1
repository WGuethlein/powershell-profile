<#
.SYNOPSIS
    Shows password expiration details for one or more AD users.
.DESCRIPTION
    Uses the computed attribute msDS-UserPasswordExpiryTimeComputed, so fine-grained password
    policies are honored. A value of 0 or Int64 max means the password does not expire (or
    expiry is not applicable). Returns one object per user.
.PARAMETER Username
    SamAccountName, UPN, or email address. Accepts pipeline input.
.EXAMPLE
    Get-UserPasswordExpiration -Username jdoe
.EXAMPLE
    Get-UserPasswordExpiration -Username jdoe@contoso.com
.EXAMPLE
    'jdoe','asmith' | Get-PwdExp | Format-Table
.EXAMPLE
    Get-Content C:\Temp\users.txt | Get-PwdExp | Where-Object { $_.DaysRemaining -le 14 } | Sort-Object DaysRemaining
    Lists users whose password expires within two weeks (or already has), soonest first.
.EXAMPLE
    Get-ADUser -Filter "Department -eq '1234'" | Get-PwdExp | Where-Object Expired
    Pipes AD user objects in (matched by SamAccountName) and keeps only users with an expired password.
.NOTES
    Name: Get-UserPasswordExpiration
    Version: 2.1.0
    Author: WGuethlein
    Date: 2026-10-04
    Prerequisites: ActiveDirectory module
#>
function Get-UserPasswordExpiration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('SamAccountName', 'User')]
        [string]$Username
    )

    begin {
        Assert-Module -Name ActiveDirectory
        $props = 'msDS-UserPasswordExpiryTimeComputed', 'PasswordNeverExpires', 'PasswordLastSet'
    }

    process {
        # Resolves SamAccountName, UPN or email; a miss comes back as ADUser = $null.
        $item = @(Resolve-ADUserIdentity -User $Username -Properties $props) | Select-Object -First 1
        if ($null -eq $item) { return }
        if ($null -eq $item.ADUser) {
            Write-Warning "User not found: $($item.Input) ($($item.Error))"
            return
        }

        try {
            $user = $item.ADUser
            $raw  = $user.'msDS-UserPasswordExpiryTimeComputed'

            $expiresOn = $null
            $daysRemaining = $null
            $expired = $false
            if ($null -ne $raw -and $raw -ne 0 -and $raw -ne [int64]::MaxValue) {
                $expiresOn = [datetime]::FromFileTime([int64]$raw)
                $daysRemaining = [int][math]::Floor(($expiresOn - (Get-Date)).TotalDays)
                $expired = $expiresOn -lt (Get-Date)
            }

            [PSCustomObject]@{
                User                 = $user.SamAccountName
                PasswordLastSet      = $user.PasswordLastSet
                PasswordNeverExpires = [bool]$user.PasswordNeverExpires
                ExpiresOn            = $expiresOn
                DaysRemaining        = $daysRemaining
                Expired              = $expired
            }
        }
        catch {
            Write-Error "Error retrieving password information for $Username : $($_.Exception.Message)"
        }
    }
}

Set-Alias -Name Get-PwdExp -Value Get-UserPasswordExpiration
