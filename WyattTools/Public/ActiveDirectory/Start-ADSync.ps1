<#
.SYNOPSIS
    Triggers an AD Sync cycle on a remote Azure AD Connect server.
.DESCRIPTION
    Connects via PowerShell remoting and runs Start-ADSyncSyncCycle with the chosen policy.
    The server defaults to AADConnectServer from the WyattTools config. Always returns a result
    object (also on failure) so callers can check .Success.
.PARAMETER ComputerName
    Azure AD Connect server. Default: AADConnectServer from config.
.PARAMETER PolicyType
    Delta (default) or Initial.
.EXAMPLE
    Start-ADSync
    Triggers a delta sync on the configured server.
.EXAMPLE
    if ((Start-ADSync -PolicyType Initial).Success) { 'queued' }
.EXAMPLE
    Start-ADSync -ComputerName 'sync01.contoso.com' -PolicyType Delta -WhatIf
    Previews a delta sync against a specific server instead of the configured one.
.EXAMPLE
    $r = Start-ADSync; if (-not $r.Success) { Write-Warning $r.Message }
    Captures the result object and reports the failure reason.
.NOTES
    Name: Start-ADSync
    Version: 2.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: PowerShell remoting to the sync server, ADSync module on that server, admin rights there
#>
function Start-ADSync {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = (Get-WyattConfig).AADConnectServer,

        [Parameter()]
        [ValidateSet('Delta', 'Initial')]
        [string]$PolicyType = 'Delta'
    )

    # Single result object, filled in on every path and returned once at the end.
    $out = [PSCustomObject]@{
        ComputerName = $ComputerName
        Success      = $false
        Message      = $null
        Result       = $null
    }

    try {
        Write-Host "Connecting to remote server: $ComputerName..." -ForegroundColor Cyan

        if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
            throw "Unable to reach server $ComputerName. Please verify network connectivity."
        }
        Write-Verbose "Server connectivity verified"

        if ($PSCmdlet.ShouldProcess($ComputerName, "Start AD Sync $PolicyType Cycle")) {
            Write-Host "Triggering AD Sync $PolicyType cycle on $ComputerName..." -ForegroundColor Cyan

            $remote = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param($Policy)
                try {
                    if (-not (Get-Module -ListAvailable -Name ADSync)) {
                        return @{ Success = $false; Message = "ADSync module not found on remote server"; Result = $null }
                    }
                    Import-Module ADSync -ErrorAction Stop
                    $syncResult = Start-ADSyncSyncCycle -PolicyType $Policy -ErrorAction Stop
                    return @{ Success = $true; Message = "Sync cycle triggered successfully"; Result = $syncResult }
                }
                catch {
                    return @{ Success = $false; Message = $_.Exception.Message; Result = $null }
                }
            } -ArgumentList $PolicyType -ErrorAction Stop

            $out.Success = [bool]$remote.Success
            $out.Message = $remote.Message
            $out.Result  = $remote.Result

            if ($out.Success) {
                Write-Host "`nSUCCESS: AD Sync $PolicyType cycle triggered on $ComputerName" -ForegroundColor Green
                if ($out.Result) {
                    Write-Host "`nSync Details:" -ForegroundColor Yellow
                    Write-Host "  Result: $($out.Result.Result)" -ForegroundColor White
                    if ($out.Result.PSObject.Properties.Name -contains 'Identifier') {
                        Write-Host "  Identifier: $($out.Result.Identifier)" -ForegroundColor White
                    }
                }
                Write-Host "`nNote: The sync cycle has been queued. It may take a few moments to complete." -ForegroundColor Cyan
            }
            else {
                Write-Host "`nFAILURE: Unable to trigger sync cycle" -ForegroundColor Red
                Write-Host "  Error: $($out.Message)" -ForegroundColor Red
            }
        }
        else {
            $out.Message = "Skipped (WhatIf/Confirm declined)"
        }
    }
    catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        $out.Message = $_.Exception.Message
        Write-Host "`nFAILURE: PowerShell Remoting error" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
        Write-Host "  - Verify PowerShell Remoting is enabled on $ComputerName" -ForegroundColor White
        Write-Host "  - Run 'Enable-PSRemoting' on the remote server" -ForegroundColor White
        Write-Host "  - Check firewall rules allow WinRM traffic" -ForegroundColor White
    }
    catch [System.UnauthorizedAccessException] {
        $out.Message = $_.Exception.Message
        Write-Host "`nFAILURE: Access denied" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "`nYou need administrative privileges on $ComputerName to run this command." -ForegroundColor Yellow
    }
    catch {
        $out.Message = $_.Exception.Message
        Write-Host "`nFAILURE: An unexpected error occurred" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Verbose "Full error details: $($_ | Format-List -Force | Out-String)"
    }

    $out
}
