<#
.SYNOPSIS
    Triggers an AD Sync Delta cycle on a remote Azure AD Connect server.

.DESCRIPTION
    This script connects to a remote server via PowerShell remoting and executes
    the Start-ADSyncSyncCycle command with Delta policy. It verifies the sync
    cycle was triggered successfully and reports the result.

.EXAMPLE
    .\Start-ADSync.ps1
    Triggers a delta sync on server AADCONNECT1

.NOTES
    Name:          Start-ADSync.ps1
    Version:       1.0
    Author:        WGuethlein
    Date:          2026-02-16
#>

function Start-ADSync {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    # Variables
    $computerName = "AADCONNECT1"
    $policyType = "Delta"

    # Main execution
    try {
        Write-Host "Connecting to remote server: $computerName..." -ForegroundColor Cyan
        
        # Test remote server connectivity
        if (-not (Test-Connection -ComputerName $computerName -Count 1 -Quiet)) {
            throw "Unable to reach server $computerName. Please verify network connectivity."
        }
        
        Write-Verbose "Server connectivity verified"
        
        # Execute AD Sync command on remote server
        if ($PSCmdlet.ShouldProcess($computerName, "Start AD Sync Delta Cycle")) {
            Write-Host "Triggering AD Sync Delta cycle on $computerName..." -ForegroundColor Cyan
            
            $result = Invoke-Command -ComputerName $computerName -ScriptBlock {
                param($Policy)
                
                # Verify ADSync module is available
                if (-not (Get-Module -ListAvailable -Name ADSync)) {
                    return @{
                        Success = $false
                        Message = "ADSync module not found on remote server"
                        Result = $null
                    }
                }
                
                # Import the module
                Import-Module ADSync -ErrorAction Stop
                
                # Execute the sync cycle
                try {
                    $syncResult = Start-ADSyncSyncCycle -PolicyType $Policy -ErrorAction Stop
                    return @{
                        Success = $true
                        Message = "Sync cycle triggered successfully"
                        Result = $syncResult
                    }
                }
                catch {
                    return @{
                        Success = $false
                        Message = $_.Exception.Message
                        Result = $null
                    }
                }
            } -ArgumentList $policyType -ErrorAction Stop
            
            # Process the result
            if ($result.Success) {
                Write-Host "`nSUCCESS: AD Sync Delta cycle triggered on $computerName" -ForegroundColor Green
                
                if ($result.Result) {
                    Write-Host "`nSync Details:" -ForegroundColor Yellow
                    Write-Host "  Result: $($result.Result.Result)" -ForegroundColor White
                    
                    # Additional details if available
                    if ($result.Result.PSObject.Properties.Name -contains 'Identifier') {
                        Write-Host "  Identifier: $($result.Result.Identifier)" -ForegroundColor White
                    }
                }
                
                Write-Host "`nNote: The sync cycle has been queued. It may take a few moments to complete." -ForegroundColor Cyan
            }
            else {
                Write-Host "`nFAILURE: Unable to trigger sync cycle" -ForegroundColor Red
                Write-Host "  Error: $($result.Message)" -ForegroundColor Red
                return
            }
        }
    }
    catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        Write-Host "`nFAILURE: PowerShell Remoting error" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
        Write-Host "  - Verify PowerShell Remoting is enabled on $computerName" -ForegroundColor White
        Write-Host "  - Run 'Enable-PSRemoting' on the remote server" -ForegroundColor White
        Write-Host "  - Check firewall rules allow WinRM traffic" -ForegroundColor White
    }
    catch [System.UnauthorizedAccessException] {
        Write-Host "`nFAILURE: Access denied" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "`nYou need administrative privileges on $computerName to run this command." -ForegroundColor Yellow
    }
    catch {
        Write-Host "`nFAILURE: An unexpected error occurred" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Verbose "Full error details: $($_ | Format-List -Force | Out-String)"
    }
}