<#
.SYNOPSIS
    Returns this machine's public (internet-facing) IP address.
.DESCRIPTION
    Queries api.ipify.org and falls back to ifconfig.me if the first service fails.
    Returns the address as a string. Enables TLS 1.2 on Windows PowerShell 5.1.
.EXAMPLE
    Get-PublicIP
.NOTES
    Name: Get-PublicIP
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: Internet access (Windows PowerShell 5.1 or PowerShell 7)
#>
function Get-PublicIP {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    try {
        $result = Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 5 -ErrorAction Stop
        return [string]$result.ip
    }
    catch {
        Write-Verbose "ipify failed: $($_.Exception.Message). Trying ifconfig.me."
    }

    try {
        $result = Invoke-RestMethod -Uri 'https://ifconfig.me/ip' -TimeoutSec 5 -ErrorAction Stop
        return ([string]$result).Trim()
    }
    catch {
        Write-Error "Could not determine public IP: $($_.Exception.Message)"
    }
}
