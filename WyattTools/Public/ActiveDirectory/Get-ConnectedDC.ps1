<#
.SYNOPSIS
    Shows which domain controller this machine and session are talking to.
.DESCRIPTION
    Reports three views of "my DC", because they can differ:
      LogonServer   - the DC that authenticated your current logon ($env:LOGONSERVER).
      SecureChannel - the DC this computer's Netlogon secure channel is bound to (nltest /sc_query).
      LocatorDC     - the DC the DC locator returns right now, with its IP, site and OS.
    Uses .NET System.DirectoryServices and nltest, so the ActiveDirectory module (RSAT) is not required.
.PARAMETER Domain
    DNS domain to query. Default: $env:USERDNSDOMAIN.
.EXAMPLE
    Get-ConnectedDC
.EXAMPLE
    mydc
.EXAMPLE
    mydc -Domain contoso.com | Select-Object LogonServer, SecureChannel, LocatorDC, LocatorSite
    Queries a specific domain and shows whether the three views of "my DC" agree.
.NOTES
    Name: Get-ConnectedDC
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-05
    Prerequisites: Domain-joined machine; no elevation required
#>
function Get-ConnectedDC {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN
    )

    $out = [PSCustomObject]@{
        Domain         = $Domain
        ComputerSite   = $null
        LogonServer    = $null
        SecureChannel  = $null
        ChannelStatus  = $null
        LocatorDC      = $null
        LocatorIP      = $null
        LocatorSite    = $null
        LocatorOS      = $null
    }

    if ($env:LOGONSERVER) { $out.LogonServer = $env:LOGONSERVER.TrimStart('\') }

    try {
        $out.ComputerSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
    }
    catch { Write-Verbose "Could not determine computer site: $($_.Exception.Message)" }

    # Secure channel: parse the "Trusted DC Name" and "Trusted DC Connection Status" lines.
    try {
        $nltest = @(& nltest.exe "/sc_query:$Domain" 2>&1 | ForEach-Object { [string]$_ })
        foreach ($line in $nltest) {
            if ($line.StartsWith('Trusted DC Name')) {
                $out.SecureChannel = $line.Substring('Trusted DC Name'.Length).Trim().TrimStart('\')
            }
            elseif ($line.StartsWith('Trusted DC Connection Status')) {
                $out.ChannelStatus = $line.Substring($line.LastIndexOf(' ') + 1)
            }
        }
        if (-not $out.SecureChannel) { Write-Verbose "nltest output: $($nltest -join ' | ')" }
    }
    catch { Write-Verbose "nltest failed: $($_.Exception.Message)" }

    try {
        $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        $dc = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($context)
        $out.LocatorDC   = $dc.Name
        $out.LocatorIP   = $dc.IPAddress
        $out.LocatorSite = $dc.SiteName
        $out.LocatorOS   = $dc.OSVersion
    }
    catch { Write-Warning "DC locator failed for ${Domain}: $($_.Exception.Message)" }

    Write-Host "Domain controller for $Domain (computer site: $($out.ComputerSite))" -ForegroundColor Cyan
    Write-Host "  Logon server   : $($out.LogonServer)" -ForegroundColor White
    $channelColor = 'White'
    if ($out.ChannelStatus -and $out.ChannelStatus -ne 'NERR_Success') { $channelColor = 'Red' }
    Write-Host "  Secure channel : $($out.SecureChannel) ($($out.ChannelStatus))" -ForegroundColor $channelColor
    Write-Host "  Locator DC     : $($out.LocatorDC)  $($out.LocatorIP)  site $($out.LocatorSite)" -ForegroundColor White

    $out
}

Set-Alias -Name mydc -Value Get-ConnectedDC
