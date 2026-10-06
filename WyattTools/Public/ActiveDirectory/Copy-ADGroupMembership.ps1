<#
.SYNOPSIS
    Copies direct group memberships from one AD user to another.
.DESCRIPTION
    Adds the target user to every direct group of the source user that the target is not already a
    direct member of. Never removes anything. Groups in -ExcludeGroup (by name) are skipped. A
    transcript is written to %TEMP%. Returns one result object per group.
.PARAMETER SourceUser
    SamAccountName, UPN, or email of the user to copy from.
.PARAMETER TargetUser
    SamAccountName, UPN, or email of the user to copy to.
.PARAMETER ExcludeGroup
    Group names to skip. Default: Domain Users.
.EXAMPLE
    Copy-ADGroupMembership -SourceUser jdoe -TargetUser asmith -WhatIf
.EXAMPLE
    Copy-ADGroupMembership -SourceUser jdoe -TargetUser asmith -ExcludeGroup 'Domain Users','VPN Users'
.EXAMPLE
    Copy-ADGroupMembership jdoe@contoso.com asmith@contoso.com | Format-Table
    Uses email addresses (positional) and shows what happened to each group: Added, AlreadyMember, Excluded, or Failed.
.EXAMPLE
    Copy-ADGroupMembership -SourceUser jdoe -TargetUser asmith | Where-Object Status -eq 'Failed'
    Runs the copy and lists only the groups that could not be added.
.NOTES
    Name: Copy-ADGroupMembership
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: ActiveDirectory module, rights to modify the groups
#>
function Copy-ADGroupMembership {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceUser,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetUser,

        [Parameter()]
        [string[]]$ExcludeGroup = @('Domain Users')
    )

    Assert-Module -Name ActiveDirectory

    $src = Resolve-ADUserIdentity -User $SourceUser -Properties MemberOf
    $tgt = Resolve-ADUserIdentity -User $TargetUser -Properties MemberOf
    if ($null -eq $src.ADUser) { Write-Error "Source user not found: $SourceUser ($($src.Error))"; return }
    if ($null -eq $tgt.ADUser) { Write-Error "Target user not found: $TargetUser ($($tgt.Error))"; return }

    $transcriptPath = Join-Path $env:TEMP "Copy-ADGroupMembership_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $transcriptPath -WhatIf:$false | Out-Null

    $added = 0
    $skipped = 0
    $failed = 0
    $targetDns = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($dn in @($tgt.ADUser.MemberOf)) { [void]$targetDns.Add($dn) }

    try {
        Write-Host "Copying groups: $($src.ADUser.SamAccountName) -> $($tgt.ADUser.SamAccountName)" -ForegroundColor Cyan

        foreach ($dn in @($src.ADUser.MemberOf)) {
            if (-not $dn) { continue }
            $name = ((($dn -split '(?<!\\),')[0]) -replace '^CN=', '') -replace '\\(.)', '$1'
            $status = $null

            if ($ExcludeGroup -contains $name) {
                Write-Verbose "Excluded: $name"
                $status = 'Excluded'
                $skipped++
            }
            elseif ($targetDns.Contains($dn)) {
                Write-Verbose "Already a direct member: $name"
                $status = 'AlreadyMember'
                $skipped++
            }
            elseif ($PSCmdlet.ShouldProcess($tgt.ADUser.SamAccountName, "Add to $name")) {
                try {
                    Add-ADGroupMember -Identity $dn -Members $tgt.ADUser -ErrorAction Stop
                    Write-Host "Added: $name" -ForegroundColor Green
                    $status = 'Added'
                    $added++
                }
                catch {
                    Write-Host "Failed: $name - $($_.Exception.Message)" -ForegroundColor Red
                    $status = 'Failed'
                    $failed++
                }
            }
            else {
                $status = 'WhatIf'
            }

            [PSCustomObject]@{
                Group  = $name
                Status = $status
            }
        }

        Write-Host ""
        Write-Host "========== Summary ==========" -ForegroundColor Cyan
        Write-Host "Added: $added" -ForegroundColor Green
        Write-Host "Skipped: $skipped" -ForegroundColor Gray
        Write-Host "Failed: $failed" -ForegroundColor Red
        Write-Host "Transcript: $transcriptPath" -ForegroundColor Cyan
    }
    finally {
        $WhatIfPreference = $false  # Stop-Transcript has no -WhatIf in 5.1; must really stop
        Stop-Transcript | Out-Null
    }
}
