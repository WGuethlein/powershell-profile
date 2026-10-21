<#
.SYNOPSIS
    Restarts explorer.exe for one user, or every logged-on user, on one or more computers.
.DESCRIPTION
    Uses a single Invoke-Command (PowerShell remoting) across all targets; the local computer is
    handled directly without remoting. On each target, every explorer.exe in a user's session is
    stopped together (there can be more than one when folder windows run in a separate process),
    then the session is watched for a new explorer.exe. Windows normally restarts the shell on its
    own; if it does not within -WaitSeconds, a one-time scheduled task running as that user starts
    explorer.exe in their interactive session and is removed afterwards. Unreachable computers and
    computers with no matching explorer.exe produce an object with the Error property set.
.PARAMETER ComputerName
    One or more computer names. Accepts pipeline input.
.PARAMETER UserName
    sAMAccountName (or DOMAIN\user) whose explorer to restart. Omit to restart explorer in every session.
.PARAMETER Credential
    Optional credential for remote connections.
.PARAMETER WaitSeconds
    How long to wait for Windows to restart explorer on its own before using the scheduled task. Default 10.
.PARAMETER ThrottleLimit
    Maximum concurrent remote connections. Default 32.
.EXAMPLE
    Restart-RemoteExplorer PC1234 -UserName jdoe
.EXAMPLE
    Restart-RemoteExplorer PC1234 -WhatIf
    Shows which computer would have explorer restarted in every session, without stopping anything.
.EXAMPLE
    'PC1234','PC5678' | Restart-RemoteExplorer -UserName jdoe -Credential (Get-Credential) -Confirm:$false
    Restarts jdoe's explorer on two computers without a per-computer prompt.
.EXAMPLE
    Get-Content kiosks.txt | Restart-RemoteExplorer -Confirm:$false | Where-Object { $_.Error -or $_.Method -eq 'Failed' }
    Restarts explorer on a list of computers and shows only the ones that did not come back.
.NOTES
    Name: Restart-RemoteExplorer
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-21
    Prerequisites: PowerShell remoting (WinRM) enabled on remote targets; local admin on the target
    (to stop another user's process and register the fallback scheduled task).
#>
function Restart-RemoteExplorer {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Name', 'Computer')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [Parameter()]
        [string]$UserName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$WaitSeconds = 10,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$ThrottleLimit = 32
    )

    begin {
        $names = New-Object System.Collections.Generic.List[string]
        if ($UserName -match '\\') { $UserName = $UserName.Split('\')[-1] }
        $who = if ($UserName) { "explorer.exe for $UserName" } else { 'explorer.exe in every session' }

        # Runs on the target; returns one plain object per session so it serializes cleanly
        $restart = {
            param($UserName, $WaitSeconds)

            $procs = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object {
                $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
                if ($owner.ReturnValue -ne 0 -or -not $owner.User) {
                    Write-Warning "$env:COMPUTERNAME : could not read the owner of explorer.exe PID $($_.ProcessId); skipped."
                    return
                }
                [PSCustomObject]@{
                    ProcessId = $_.ProcessId
                    SessionId = $_.SessionId
                    Sam       = $owner.User
                    User      = "$($owner.Domain)\$($owner.User)"
                }
            })
            if ($UserName) { $procs = @($procs | Where-Object { $_.Sam -eq $UserName }) }

            if ($procs.Count -eq 0) {
                $target = if ($UserName) { "for '$UserName'" } else { 'in any session' }
                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME; User = $UserName; SessionId = $null
                    OldPid = @(); NewPid = $null; Method = $null
                    Error = "No explorer.exe found $target"
                }
                return
            }

            foreach ($session in ($procs | Group-Object -Property SessionId)) {
                $sessionId = [int]$session.Name
                $user = $session.Group[0].User
                $oldPids = @($session.Group | ForEach-Object { $_.ProcessId })
                $err = $null

                # A new explorer in this session that is not one of the processes just stopped
                $findNew = {
                    Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe' AND SessionId=$sessionId" |
                        Where-Object { $oldPids -notcontains $_.ProcessId } |
                        Select-Object -First 1
                }

                foreach ($procId in $oldPids) {
                    Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                }

                $deadline = (Get-Date).AddSeconds($WaitSeconds)
                do {
                    Start-Sleep -Seconds 1
                    $new = & $findNew
                } until ($new -or (Get-Date) -gt $deadline)

                $method = 'AutoRestart'
                if (-not $new) {
                    $method = 'ScheduledTask'
                    $task = 'RestartExplorer-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
                    try {
                        $action = New-ScheduledTaskAction -Execute "$env:windir\explorer.exe"
                        $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive
                        Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force -ErrorAction Stop | Out-Null
                        Start-ScheduledTask -TaskName $task -ErrorAction Stop
                        Start-Sleep -Seconds 3
                        $new = & $findNew
                    }
                    catch {
                        $err = "Scheduled task fallback failed: $($_.Exception.Message)"
                    }
                    finally {
                        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
                    }
                    if (-not $new) { $method = 'Failed' }
                }

                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    User         = $user
                    SessionId    = $sessionId
                    OldPid       = $oldPids
                    NewPid       = if ($new) { $new.ProcessId } else { $null }
                    Method       = $method
                    Error        = $err
                }
            }
        }

        $properties = 'ComputerName', 'User', 'SessionId', 'OldPid', 'NewPid', 'Method', 'Error'
    }

    process {
        foreach ($n in $ComputerName) {
            if ($PSCmdlet.ShouldProcess($n, "Restart $who")) { $names.Add($n) }
        }
    }

    end {
        $localNames = @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
        $remote = @($names | Where-Object { $localNames -notcontains $_ } | Select-Object -Unique)
        $hasLocal = [bool]($names | Where-Object { $localNames -contains $_ })

        if ($hasLocal) {
            & $restart $UserName $WaitSeconds | Select-Object -Property $properties
        }

        if ($remote.Count -gt 0) {
            $invokeParams = @{
                ComputerName  = $remote
                ScriptBlock   = $restart
                ArgumentList  = $UserName, $WaitSeconds
                ThrottleLimit = $ThrottleLimit
                ErrorVariable = 'remoteErrors'
                ErrorAction   = 'SilentlyContinue'
            }
            if ($Credential) { $invokeParams.Credential = $Credential }

            Invoke-Command @invokeParams | Select-Object -Property $properties

            # One error object per unreachable host
            foreach ($e in $remoteErrors) {
                $target = $e.TargetObject
                if ($target -isnot [string]) { $target = $e.CategoryInfo.TargetName }
                if (-not $target) { $target = ($remote -join ',') }
                Write-Verbose "Error for ${target}: $($e.Exception.Message)"
                [PSCustomObject]@{
                    ComputerName = $target; User = $UserName; SessionId = $null
                    OldPid = @(); NewPid = $null; Method = $null
                    Error = $e.Exception.Message.Trim()
                }
            }
        }
    }
}
