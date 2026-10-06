<#
.SYNOPSIS
    Gathers OS, uptime, user, hardware, and disk info from one or more computers.
.DESCRIPTION
    Uses a single Invoke-Command (PowerShell remoting) across all targets, with Get-CimInstance
    inside. The local computer is queried directly without remoting. Unreachable computers produce
    an object with the Error property set instead of stopping the run.
.PARAMETER ComputerName
    One or more computer names. Defaults to the local computer. Accepts pipeline input.
.PARAMETER Credential
    Optional credential for remote connections.
.PARAMETER ThrottleLimit
    Maximum concurrent remote connections. Default 32.
.EXAMPLE
    Get-RemoteSystemInfo
.EXAMPLE
    'srv01','srv02' | Get-RemoteSystemInfo -Credential (Get-Credential) | Format-Table ComputerName, OS, Uptime, DiskSummary
.EXAMPLE
    Get-RemoteSystemInfo -ComputerName srv01,srv02,srv03 -ThrottleLimit 10 | Select-Object ComputerName, OS, Uptime, MemoryGB, DiskSummary
    Queries several servers at once, limited to 10 concurrent connections.
.EXAMPLE
    Get-Content servers.txt | Get-RemoteSystemInfo | Where-Object { $_.Error }
    Reads server names from a file and shows only the ones that could not be reached, with the error text.
.EXAMPLE
    Get-RemoteSystemInfo srv01 | Select-Object -ExpandProperty Disks | Format-Table DeviceID, SizeGB, FreeGB, FreePct
    Shows the per-drive detail instead of the one-line DiskSummary.
.NOTES
    Name: Get-RemoteSystemInfo
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: PowerShell remoting (WinRM) enabled on remote targets
#>
function Get-RemoteSystemInfo {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$ThrottleLimit = 32
    )

    begin {
        $names = New-Object System.Collections.Generic.List[string]

        # Runs on the target; returns plain data so it serializes cleanly
        $gather = {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem
            $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
                $size = [math]::Round($_.Size / 1GB, 1)
                $free = [math]::Round($_.FreeSpace / 1GB, 1)
                $pct = if ($_.Size) { [int][math]::Round(100 * $_.FreeSpace / $_.Size) } else { 0 }
                [PSCustomObject]@{ DeviceID = $_.DeviceID; SizeGB = $size; FreeGB = $free; FreePct = $pct }
            })
            $up = (Get-Date) - $os.LastBootUpTime
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                OS           = $os.Caption
                Version      = $os.Version
                LastBoot     = $os.LastBootUpTime
                Uptime       = '{0}d {1}h {2}m' -f $up.Days, $up.Hours, $up.Minutes
                LoggedOnUser = $cs.UserName
                Model        = ('{0} {1}' -f $cs.Manufacturer, $cs.Model).Trim()
                MemoryGB     = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
                Disks        = $disks
            }
        }

        # Builds the final output object (with DiskSummary) from raw gathered data
        function ConvertTo-SystemInfoResult {
            param($Data)
            $summary = (@($Data.Disks) | ForEach-Object {
                '{0} {1}/{2} GB free ({3}%)' -f $_.DeviceID, $_.FreeGB, $_.SizeGB, $_.FreePct
            }) -join '; '
            [PSCustomObject]@{
                ComputerName = $Data.ComputerName
                OS           = $Data.OS
                Version      = $Data.Version
                LastBoot     = $Data.LastBoot
                Uptime       = $Data.Uptime
                LoggedOnUser = $Data.LoggedOnUser
                Model        = $Data.Model
                MemoryGB     = $Data.MemoryGB
                Disks        = @($Data.Disks)
                DiskSummary  = $summary
                Error        = $null
            }
        }

        function Get-SystemInfoErrorObject {
            param([string]$Name, [string]$Message)
            [PSCustomObject]@{
                ComputerName = $Name; OS = $null; Version = $null; LastBoot = $null; Uptime = $null
                LoggedOnUser = $null; Model = $null; MemoryGB = $null; Disks = @(); DiskSummary = $null
                Error = $Message
            }
        }
    }

    process {
        foreach ($n in $ComputerName) { $names.Add($n) }
    }

    end {
        $localNames = @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
        $remote = @($names | Where-Object { $localNames -notcontains $_ } | Select-Object -Unique)
        $hasLocal = [bool]($names | Where-Object { $localNames -contains $_ })

        if ($hasLocal) {
            try {
                ConvertTo-SystemInfoResult -Data (& $gather)
            }
            catch {
                Write-Warning "Local query failed: $($_.Exception.Message)"
                Get-SystemInfoErrorObject -Name $env:COMPUTERNAME -Message $_.Exception.Message
            }
        }

        if ($remote.Count -gt 0) {
            $invokeParams = @{
                ComputerName  = $remote
                ScriptBlock   = $gather
                ThrottleLimit = $ThrottleLimit
                ErrorVariable = 'remoteErrors'
                ErrorAction   = 'SilentlyContinue'
            }
            if ($Credential) { $invokeParams.Credential = $Credential }

            $results = @(Invoke-Command @invokeParams)
            foreach ($r in $results) { ConvertTo-SystemInfoResult -Data $r }

            # One error object per unreachable host
            foreach ($e in $remoteErrors) {
                $target = $e.TargetObject
                if ($target -isnot [string]) { $target = $e.CategoryInfo.TargetName }
                if (-not $target) { $target = ($remote -join ',') }
                Write-Verbose "Error for ${target}: $($e.Exception.Message)"
                Get-SystemInfoErrorObject -Name $target -Message $e.Exception.Message.Trim()
            }
        }
    }
}
