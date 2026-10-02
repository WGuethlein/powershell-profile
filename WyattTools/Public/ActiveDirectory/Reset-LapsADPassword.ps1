<#
.SYNOPSIS
    Expires a computer's Windows LAPS password in AD so the device rotates it.
.DESCRIPTION
    Wrapper around Set-LapsADPasswordExpirationTime from the built-in LAPS module. Setting the
    expiration to now marks the password expired; the device generates and backs up a new one
    at its next LAPS policy processing cycle (typically within an hour). Works while the device
    is offline - it rotates when it next processes policy. Named Reset-LapsADPassword so it does
    not shadow the LAPS module's Reset-LapsPassword, which resets on the local device.
.PARAMETER ComputerName
    AD computer name(s). Accepts pipeline input (including objects from Get-ADComputer).
.EXAMPLE
    Reset-LapsADPassword PC1234
.EXAMPLE
    'PC1234','PC5678' | Reset-LapsADPassword -WhatIf
.NOTES
    Name: Reset-LapsADPassword
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: Windows LAPS module (built into Windows), reset-password rights on the computer object.
#>
function Reset-LapsADPassword {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Name', 'Identity', 'Computer')]
        [string[]]$ComputerName
    )

    begin {
        Assert-Module -Name LAPS
    }

    process {
        foreach ($computer in $ComputerName) {
            if (-not $PSCmdlet.ShouldProcess($computer, 'Expire LAPS password (rotates at next policy cycle)')) { continue }

            try {
                # No -WhenEffective = expire immediately.
                $result = Set-LapsADPasswordExpirationTime -Identity $computer -ErrorAction Stop
                Write-Host "$computer : LAPS password expired; it rotates at the device's next policy cycle." -ForegroundColor Green
                [PSCustomObject]@{
                    ComputerName      = $computer
                    DistinguishedName = $result.DistinguishedName
                    Status            = $result.Status
                }
            }
            catch {
                Write-Error "Failed to expire LAPS password for '$computer': $($_.Exception.Message)"
            }
        }
    }
}

Set-Alias -Name lapsreset -Value Reset-LapsADPassword
