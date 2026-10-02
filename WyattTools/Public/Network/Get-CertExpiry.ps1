<#
.SYNOPSIS
    Reports the TLS certificate expiry for one or more hosts.
.DESCRIPTION
    Connects to each host over TCP, performs a TLS handshake, and reads the server certificate.
    Certificate trust is NOT validated (the certificate is only read), so expired or self-signed
    certificates are reported rather than rejected. Accepts 'host', 'host:port', or a URL.
.PARAMETER HostName
    One or more targets: 'host', 'host:port', or 'https://host/path'. Accepts pipeline input.
.PARAMETER Port
    Port used when the target does not specify one. Default 443.
.PARAMETER WarnDays
    Status is 'Expiring' when this many days or fewer remain. Default 30.
.EXAMPLE
    Get-CertExpiry github.com
.EXAMPLE
    'https://www.microsoft.com/en-us','mail.contoso.com:993' | Get-CertExpiry -WarnDays 60
.NOTES
    Name: Get-CertExpiry
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None (Windows PowerShell 5.1 or PowerShell 7)
#>
function Get-CertExpiry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$HostName,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = 443,

        [Parameter()]
        [int]$WarnDays = 30
    )

    begin {
        $timeoutMs = 5000
    }

    process {
        foreach ($target in $HostName) {
            $targetHost = $target.Trim()
            $targetPort = $Port

            # Parse URL, host:port, or bare host. URL without explicit port uses the scheme default
            # (https -> 443), unless the scheme has no known port, in which case -Port applies.
            if ($targetHost -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
                try {
                    $uri = [uri]$targetHost
                    $targetHost = $uri.Host
                    if ($uri.Port -gt 0) { $targetPort = $uri.Port }
                }
                catch {
                    Write-Warning "Cannot parse '$target': $($_.Exception.Message)"
                    [PSCustomObject]@{
                        HostName = $target; Port = $Port; Subject = $null; Issuer = $null; NotBefore = $null
                        NotAfter = $null; DaysRemaining = $null; Status = 'Error'; Thumbprint = $null
                    }
                    continue
                }
            }
            elseif ($targetHost -match '^([^:]+):(\d+)$') {
                $targetHost = $Matches[1]
                $targetPort = [int]$Matches[2]
            }

            $client = $null
            $ssl = $null
            try {
                $client = New-Object System.Net.Sockets.TcpClient
                $connect = $client.ConnectAsync($targetHost, $targetPort)
                if (-not $connect.Wait($timeoutMs)) { throw "Connection timed out after $timeoutMs ms." }

                $stream = $client.GetStream()
                $stream.ReadTimeout = $timeoutMs
                $stream.WriteTimeout = $timeoutMs

                # Always accept the certificate: we only want to read it
                $callback = [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
                $ssl = New-Object System.Net.Security.SslStream($stream, $false, $callback)
                $ssl.AuthenticateAsClient($targetHost)

                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
                $days = [int][math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
                $status = if ($days -lt 0) { 'Expired' } elseif ($days -le $WarnDays) { 'Expiring' } else { 'OK' }

                [PSCustomObject]@{
                    HostName      = $targetHost
                    Port          = $targetPort
                    Subject       = $cert.Subject
                    Issuer        = $cert.Issuer
                    NotBefore     = $cert.NotBefore
                    NotAfter      = $cert.NotAfter
                    DaysRemaining = $days
                    Status        = $status
                    Thumbprint    = $cert.Thumbprint
                }
            }
            catch {
                $msg = $_.Exception.Message
                if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
                Write-Warning "${targetHost}:${targetPort} - $msg"
                [PSCustomObject]@{
                    HostName = $targetHost; Port = $targetPort; Subject = $null; Issuer = $null; NotBefore = $null
                    NotAfter = $null; DaysRemaining = $null; Status = 'Error'; Thumbprint = $null
                }
            }
            finally {
                if ($ssl) { $ssl.Dispose() }
                if ($client) { $client.Dispose() }
            }
        }
    }
}
