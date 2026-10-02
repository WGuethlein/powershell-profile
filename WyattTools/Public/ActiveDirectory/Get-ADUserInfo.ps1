<#
.SYNOPSIS
    Returns a consolidated account summary for one AD user.
.DESCRIPTION
    Resolves a SamAccountName, UPN, or email address to an AD user and returns one object with
    identity, status, password, logon, organisation, and group membership details. PasswordExpires
    comes from msDS-UserPasswordExpiryTimeComputed and is $null when the password never expires.
    LastLogon is LastLogonDate (replicated LastLogonTimestamp) and can lag by up to 14 days.
    MemberOf lists direct group names (CN only), sorted.
.PARAMETER Identity
    SamAccountName, UPN, or email address. Accepts pipeline input.
.EXAMPLE
    Get-ADUserInfo jdoe
.EXAMPLE
    adinfo jdoe@contoso.com | Format-List
.NOTES
    Name: Get-ADUserInfo
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: ActiveDirectory module
#>
function Get-ADUserInfo {
    [CmdletBinding()]
    [Alias('adinfo')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('SamAccountName', 'User')]
        [string[]]$Identity
    )

    begin {
        Assert-Module -Name ActiveDirectory
        $props = 'LockedOut', 'PasswordLastSet', 'PasswordNeverExpires', 'LastLogonDate', 'whenCreated',
                 'Title', 'Department', 'Manager', 'MemberOf', 'EmailAddress', 'msDS-UserPasswordExpiryTimeComputed'
    }

    process {
        foreach ($item in @(Resolve-ADUserIdentity -User $Identity -Properties $props)) {
            if ($null -eq $item.ADUser) {
                Write-Warning "User not found: $($item.Input) ($($item.Error))"
                continue
            }
            $u = $item.ADUser

            # 0 or Int64.MaxValue means the password never expires.
            $expires = $null
            $raw = $u.'msDS-UserPasswordExpiryTimeComputed'
            if ($null -ne $raw -and [int64]$raw -ne 0 -and [int64]$raw -ne [int64]::MaxValue) {
                $expires = [datetime]::FromFileTime([int64]$raw)
            }

            $managerName = $null
            if ($u.Manager) {
                try { $managerName = (Get-ADUser -Identity $u.Manager -ErrorAction Stop).SamAccountName }
                catch { $managerName = $u.Manager; Write-Verbose "Manager lookup failed: $_" }
            }

            # CN is the first RDN of the DN; split on commas that are not escaped.
            $groups = foreach ($dn in @($u.MemberOf)) {
                if ($dn) { ((($dn -split '(?<!\\),')[0]) -replace '^CN=', '') -replace '\\(.)', '$1' }
            }

            [PSCustomObject]@{
                Name                 = $u.Name
                SamAccountName       = $u.SamAccountName
                UPN                  = $u.UserPrincipalName
                EmailAddress         = $u.EmailAddress
                Enabled              = $u.Enabled
                LockedOut            = $u.LockedOut
                PasswordLastSet      = $u.PasswordLastSet
                PasswordExpires      = $expires
                PasswordNeverExpires = $u.PasswordNeverExpires
                LastLogon            = $u.LastLogonDate
                whenCreated          = $u.whenCreated
                Title                = $u.Title
                Department           = $u.Department
                Manager              = $managerName
                DistinguishedName    = $u.DistinguishedName
                MemberOf             = @($groups | Sort-Object)
            }
        }
    }
}
