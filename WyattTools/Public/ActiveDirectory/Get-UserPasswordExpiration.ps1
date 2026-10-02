<#
.SYNOPSIS
    Shows password expiration details for one or more AD users.
.DESCRIPTION
    Uses the computed attribute msDS-UserPasswordExpiryTimeComputed, so fine-grained password
    policies are honored. A value of 0 or Int64 max means the password does not expire (or
    expiry is not applicable). Returns one object per user.
.PARAMETER Username
    SamAccountName (or other Get-ADUser identity). Accepts pipeline input.
.EXAMPLE
    Get-UserPasswordExpiration -Username jdoe
.EXAMPLE
    'jdoe','asmith' | Get-PwdExp | Format-Table
.NOTES
    Name: Get-UserPasswordExpiration
    Version: 2.0.0
    Author: WGuethlein
    Date: 2026-10-02
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
        try {
            $user = Get-ADUser -Identity $Username -Properties $props -ErrorAction Stop
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
