#Requires -Version 5.1
<#
.SYNOPSIS
    Lightweight API endpoint testing helpers (GET/POST) with a status/timing wrapper.

.DESCRIPTION
    Defines Invoke-ApiGet and Invoke-ApiPost plus 'get'/'post' aliases for quick
    interactive endpoint testing. Each call returns a PSCustomObject exposing the
    HTTP status code, elapsed milliseconds, the parsed body, and the raw body string.
    Non-2xx responses are captured (not thrown) so error payloads are inspectable.
    Intended to be dot-sourced from a PowerShell profile.

.NOTES
    Name        : ApiTestHelpers.ps1
    Version     : 1.0.0
    Author      : Wyatt
    Date        : 2026-06-23
    Prerequisite: Windows PowerShell 5.1
    Usage       : . "C:\path\to\ApiTestHelpers.ps1"
                  get  https://api.example.com/users/5
                  post https://api.example.com/users '{"name":"Ada"}'
#>

# ---------------------------------------------------------------------------
# Variables (configurable defaults)
# ---------------------------------------------------------------------------

# Default Content-Type applied to request bodies on POST.
$script:ApiDefaultContentType = 'application/json'

# ---------------------------------------------------------------------------
# Internal helper: executes the request, times it, and normalizes the result.
# Not exported as an alias; shared by the GET/POST wrappers (DRY).
# ---------------------------------------------------------------------------
function Invoke-ApiRequest {
    [CmdletBinding()]
    param(
        # HTTP method to use.
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string] $Method,

        # Full target URL.
        [Parameter(Mandatory)]
        [string] $Uri,

        # Optional raw request body (expected JSON string for POST).
        [Parameter()]
        [string] $Body,

        # Optional extra headers (e.g. @{ Authorization = "Bearer ..." }).
        [Parameter()]
        [hashtable] $Headers
    )

    # Build the splat for Invoke-WebRequest. We use Invoke-WebRequest (not
    # Invoke-RestMethod) so the status code and headers are available; the body
    # is parsed separately below.
    $requestArgs = @{
        Method      = $Method
        Uri         = $Uri
        Headers     = if ($Headers) { $Headers } else { @{} }
        ErrorAction = 'Stop'
        # Avoids dependence on IE engine availability in some 5.1 environments.
        UseBasicParsing = $true
    }

    if ($PSBoundParameters.ContainsKey('Body') -and $Body) {
        $requestArgs.Body        = $Body
        $requestArgs.ContentType = $script:ApiDefaultContentType
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        Write-Verbose "$Method $Uri"
        $response = Invoke-WebRequest @requestArgs
        $stopwatch.Stop()

        $statusCode = [int] $response.StatusCode
        $rawBody    = $response.Content
    }
    catch [System.Net.WebException] {
        # Non-2xx responses throw in 5.1. Recover the status code and the error
        # payload from the underlying response stream so they remain inspectable.
        $stopwatch.Stop()

        $webResponse = $_.Exception.Response
        if ($null -ne $webResponse) {
            $statusCode = [int] $webResponse.StatusCode

            $reader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
            try {
                $rawBody = $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }
        else {
            # No HTTP response at all (DNS failure, connection refused, timeout).
            Write-Warning "Request failed with no HTTP response: $($_.Exception.Message)"
            $statusCode = $null
            $rawBody    = $_.Exception.Message
        }
    }
    catch {
        # Anything else (malformed URI, etc.).
        $stopwatch.Stop()
        Write-Warning "Request error: $($_.Exception.Message)"
        $statusCode = $null
        $rawBody    = $_.Exception.Message
    }

    # Attempt to parse the raw body as JSON; fall back to the raw string.
    $parsedBody = $null
    if ($rawBody) {
        try {
            $parsedBody = $rawBody | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            $parsedBody = $rawBody
        }
    }

    [PSCustomObject]@{
        StatusCode = $statusCode
        ElapsedMs  = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 1)
        Body       = $parsedBody
        RawBody    = $rawBody
    }
}

# ---------------------------------------------------------------------------
# Public: GET wrapper.
# ---------------------------------------------------------------------------
function Invoke-ApiGet {
    [CmdletBinding()]
    param(
        # Full target URL.
        [Parameter(Mandatory, Position = 0)]
        [string] $Uri,

        # Optional extra headers (e.g. @{ Authorization = "Bearer ..." }).
        [Parameter(Position = 1)]
        [hashtable] $Headers
    )

    Invoke-ApiRequest -Method GET -Uri $Uri -Headers $Headers
}

# ---------------------------------------------------------------------------
# Public: POST wrapper.
# ---------------------------------------------------------------------------
function Invoke-ApiPost {
    [CmdletBinding()]
    param(
        # Full target URL.
        [Parameter(Mandatory, Position = 0)]
        [string] $Uri,

        # Raw JSON body string.
        [Parameter(Position = 1)]
        [string] $Body,

        # Optional extra headers (e.g. @{ Authorization = "Bearer ..." }).
        [Parameter(Position = 2)]
        [hashtable] $Headers
    )

    Invoke-ApiRequest -Method POST -Uri $Uri -Body $Body -Headers $Headers
}

# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------
Set-Alias -Name get  -Value Invoke-ApiGet  -Scope Global -Force
Set-Alias -Name post -Value Invoke-ApiPost -Scope Global -Force