<#
.SYNOPSIS
    Tests whether TCP ports are open on one or more computers (fast, async).
.DESCRIPTION
    Opens TCP connections to every requested port concurrently using TcpClient.ConnectAsync and
    reports whether each one answered within the timeout. Much faster than Test-NetConnection.
    DNS failures produce a warning and Open = $false rather than a terminating error.
.PARAMETER ComputerName
    One or more host names or IP addresses. Accepts pipeline input.
.PARAMETER Port
    One or more TCP ports to test.
.PARAMETER TimeoutMs
    Milliseconds to wait for each host's connections. Default 1000.
.EXAMPLE
    Test-Port localhost 135,1
.EXAMPLE
    'web01','web02' | Test-Port -Port 443
.EXAMPLE
    Test-Port -ComputerName server01 -Port 22,80,443,3389 -TimeoutMs 3000
    Checks four ports on one host at once, waiting up to 3 seconds for each host's connections.
.EXAMPLE
    'web01','web02','db01' | Test-Port -Port 443,1433 | Where-Object { -not $_.Open }
    Tests two ports on three piped hosts and shows only the ones that did not answer.
.EXAMPLE
    tp server01 5985,5986 | Format-Table ComputerName, Port, Open, ResponseMs
    Uses the tp alias to check the WinRM ports and shows the response times.
.NOTES
    Name: Test-Port
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None (Windows PowerShell 5.1 or PowerShell 7)
#>
function Test-Port {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName = 'localhost',

        [Parameter(Mandatory, Position = 1)]
        [ValidateRange(1, 65535)]
        [int[]]$Port,

        [Parameter()]
        [ValidateRange(1, 600000)]
        [int]$TimeoutMs = 1000
    )

    process {
        foreach ($computer in $ComputerName) {
            # Resolve once per host; connect to the IPv4 address
            $address = $null
            try {
                $address = [System.Net.Dns]::GetHostAddresses($computer) |
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                    Select-Object -First 1
            }
            catch {
                Write-Verbose "DNS error for ${computer}: $($_.Exception.Message)"
            }

            if (-not $address) {
                Write-Warning "Cannot resolve '$computer' to an IPv4 address."
                foreach ($p in $Port) {
                    [PSCustomObject]@{ ComputerName = $computer; Port = $p; Open = $false; ResponseMs = $null }
                }
                continue
            }

            # Start all connects at once, then stamp each as it completes
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $items = New-Object System.Collections.Generic.List[object]
            try {
                foreach ($p in $Port) {
                    $client = New-Object System.Net.Sockets.TcpClient
                    $items.Add([PSCustomObject]@{
                        Port = $p; Client = $client; Task = $client.ConnectAsync($address, $p); Ms = $null
                    })
                }

                $pending = New-Object System.Collections.Generic.List[object]
                $pending.AddRange($items)
                while ($pending.Count -gt 0) {
                    $remaining = $TimeoutMs - [int]$sw.ElapsedMilliseconds
                    if ($remaining -le 0) { break }
                    $tasks = [System.Threading.Tasks.Task[]]@($pending | ForEach-Object { $_.Task })
                    $idx = [System.Threading.Tasks.Task]::WaitAny($tasks, $remaining)
                    if ($idx -lt 0) { break }
                    $pending[$idx].Ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
                    $pending.RemoveAt($idx)
                }

                foreach ($item in $items) {
                    $isOpen = ($item.Task.Status -eq 'RanToCompletion') -and $item.Client.Connected
                    [PSCustomObject]@{
                        ComputerName = $computer
                        Port         = $item.Port
                        Open         = [bool]$isOpen
                        ResponseMs   = if ($isOpen) { $item.Ms } else { $null }
                    }
                }
            }
            finally {
                foreach ($item in $items) { $item.Client.Dispose() }
            }
        }
    }
}

Set-Alias -Name tp -Value Test-Port
