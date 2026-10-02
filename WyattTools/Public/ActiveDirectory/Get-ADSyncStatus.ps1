<#
.SYNOPSIS
    Shows Azure AD Connect scheduler state and recent sync run results.
.DESCRIPTION
    Uses PowerShell remoting to run Get-ADSyncScheduler and Get-ADSyncRunProfileResult on the sync
    server. Returns one object with the scheduler properties and a RecentRuns array, and prints a
    coloured summary (red for any run whose Result is not 'success').
.PARAMETER ComputerName
    Azure AD Connect server. Default: AADConnectServer from config.
.PARAMETER Last
    Number of recent run results to retrieve. Default 5.
.EXAMPLE
    Get-ADSyncStatus
.EXAMPLE
    (Get-ADSyncStatus -Last 10).RecentRuns | Format-Table
.NOTES
    Name: Get-ADSyncStatus
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: PowerShell remoting to the sync server, ADSync module on that server
#>
function Get-ADSyncStatus {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = (Get-WyattConfig).AADConnectServer,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$Last = 5
    )

    $out = [PSCustomObject]@{
        ComputerName            = $ComputerName
        Success                 = $false
        Message                 = $null
        SyncCycleEnabled        = $null
        SyncCycleInProgress     = $null
        StagingModeEnabled      = $null
        SchedulerSuspended      = $null
        NextSyncCyclePolicyType = $null
        NextSyncCycleStart      = $null
        RecentRuns              = @()
    }

    try {
        Write-Host "Querying AD Sync status on $ComputerName..." -ForegroundColor Cyan

        $remote = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($Count)
            try {
                if (-not (Get-Module -ListAvailable -Name ADSync)) {
                    return @{ Success = $false; Message = 'ADSync module not found on remote server' }
                }
                Import-Module ADSync -ErrorAction Stop
                $s = Get-ADSyncScheduler -ErrorAction Stop
                $runs = @(Get-ADSyncRunProfileResult -NumberRequested $Count -ErrorAction Stop |
                    ForEach-Object {
                        @{
                            ConnectorName  = $_.ConnectorName
                            RunProfileName = $_.RunProfileName
                            Result         = $_.Result
                            StartDate      = $_.StartDate
                            EndDate        = $_.EndDate
                        }
                    })
                return @{
                    Success = $true
                    Message = 'OK'
                    Sched   = @{
                        SyncCycleEnabled        = $s.SyncCycleEnabled
                        SyncCycleInProgress     = $s.SyncCycleInProgress
                        StagingModeEnabled      = $s.StagingModeEnabled
                        SchedulerSuspended      = $s.SchedulerSuspended
                        NextSyncCyclePolicyType = [string]$s.NextSyncCyclePolicyType
                        NextSyncCycleStartUtc   = $s.NextSyncCycleStartTimeInUTC
                    }
                    Runs    = $runs
                }
            }
            catch {
                return @{ Success = $false; Message = $_.Exception.Message }
            }
        } -ArgumentList $Last -ErrorAction Stop

        $out.Success = [bool]$remote.Success
        $out.Message = $remote.Message

        if ($out.Success) {
            $s = $remote.Sched
            $out.SyncCycleEnabled        = $s.SyncCycleEnabled
            $out.SyncCycleInProgress     = $s.SyncCycleInProgress
            $out.StagingModeEnabled      = $s.StagingModeEnabled
            $out.SchedulerSuspended      = $s.SchedulerSuspended
            $out.NextSyncCyclePolicyType = $s.NextSyncCyclePolicyType
            if ($s.NextSyncCycleStartUtc) {
                # Remote value is UTC; mark the kind explicitly before converting to local.
                $utc = [datetime]::SpecifyKind([datetime]$s.NextSyncCycleStartUtc, [System.DateTimeKind]::Utc)
                $out.NextSyncCycleStart = $utc.ToLocalTime()
            }
            $out.RecentRuns = @($remote.Runs | ForEach-Object {
                [PSCustomObject]@{
                    ConnectorName  = $_.ConnectorName
                    RunProfileName = $_.RunProfileName
                    Result         = $_.Result
                    StartDate      = $_.StartDate
                    EndDate        = $_.EndDate
                }
            })

            Write-Host "`nScheduler on ${ComputerName}:" -ForegroundColor Yellow
            Write-Host "  SyncCycleEnabled: $($out.SyncCycleEnabled)  InProgress: $($out.SyncCycleInProgress)  Staging: $($out.StagingModeEnabled)  Suspended: $($out.SchedulerSuspended)" -ForegroundColor White
            Write-Host "  Next cycle: $($out.NextSyncCyclePolicyType) at $($out.NextSyncCycleStart)" -ForegroundColor White
            Write-Host "Recent runs:" -ForegroundColor Yellow
            foreach ($r in $out.RecentRuns) {
                $color = 'Green'
                if ($r.Result -ne 'success') { $color = 'Red' }
                Write-Host ("  {0}  {1,-30} {2,-20} {3}" -f $r.StartDate, $r.ConnectorName, $r.RunProfileName, $r.Result) -ForegroundColor $color
            }
        }
        else {
            Write-Host "`nFAILURE: $($out.Message)" -ForegroundColor Red
        }
    }
    catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        $out.Message = $_.Exception.Message
        Write-Host "`nFAILURE: PowerShell Remoting error" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  - Verify PowerShell Remoting is enabled on $ComputerName and WinRM is allowed by the firewall" -ForegroundColor White
    }
    catch [System.UnauthorizedAccessException] {
        $out.Message = $_.Exception.Message
        Write-Host "`nFAILURE: Access denied" -ForegroundColor Red
        Write-Host "  You need administrative privileges on $ComputerName." -ForegroundColor Yellow
    }
    catch {
        $out.Message = $_.Exception.Message
        Write-Host "`nFAILURE: An unexpected error occurred" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Verbose "Full error details: $($_ | Format-List -Force | Out-String)"
    }

    $out
}
