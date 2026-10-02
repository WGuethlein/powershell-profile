<#
.SYNOPSIS
    Internal helper: executes an HTTP request, times it, and normalizes the result.
.DESCRIPTION
    Shared by Invoke-ApiGet and Invoke-ApiPost. Uses Invoke-WebRequest so the status code is
    available. Non-2xx responses are captured (not thrown) so error payloads stay inspectable.
    Works on Windows PowerShell 5.1 (WebException) and PowerShell 7 (HttpResponseException).
.PARAMETER Method
    GET or POST.
.PARAMETER Uri
    Full target URL.
.PARAMETER Body
    Optional raw request body (JSON string for POST).
.PARAMETER Headers
    Optional extra headers.
.EXAMPLE
    Invoke-ApiRequest -Method GET -Uri https://api.example.com/users/5
.NOTES
    Name: Invoke-ApiRequest
    Version: 2.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None
#>

# Default Content-Type applied to request bodies on POST.
$script:ApiDefaultContentType = 'application/json'

function Invoke-ApiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [string]$Body,

        [Parameter()]
        [hashtable]$Headers
    )

    $requestHeaders = @{}
    if ($Headers) { $requestHeaders = $Headers }

    $requestArgs = @{
        Method          = $Method
        Uri             = $Uri
        Headers         = $requestHeaders
        ErrorAction     = 'Stop'
        UseBasicParsing = $true   # avoids IE engine dependence on 5.1; ignored on 7
    }
    if ($Body) {
        $requestArgs.Body        = $Body
        $requestArgs.ContentType = $script:ApiDefaultContentType
    }

    $statusCode = $null
    $rawBody    = $null
    $stopwatch  = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        Write-Verbose "$Method $Uri"
        $response   = Invoke-WebRequest @requestArgs
        $statusCode = [int]$response.StatusCode
        $rawBody    = $response.Content
    }
    catch {
        $httpResponse = $_.Exception.Response
        if ($null -ne $httpResponse) {
            # 5.1: WebResponse (read the stream). 7: HttpResponseMessage (body is in ErrorDetails).
            $statusCode = [int]$httpResponse.StatusCode
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $rawBody = $_.ErrorDetails.Message
            }
            elseif ($httpResponse -is [System.Net.WebResponse]) {
                $reader = New-Object System.IO.StreamReader($httpResponse.GetResponseStream())
                try { $rawBody = $reader.ReadToEnd() } finally { $reader.Dispose() }
            }
            else {
                $rawBody = $_.Exception.Message
            }
        }
        else {
            # No HTTP response at all (DNS failure, connection refused, timeout, bad URI).
            Write-Warning "Request failed with no HTTP response: $($_.Exception.Message)"
            $rawBody = $_.Exception.Message
        }
    }
    finally {
        $stopwatch.Stop()
    }

    # Attempt to parse the raw body as JSON; fall back to the raw string.
    $parsedBody = $null
    if ($rawBody) {
        try { $parsedBody = $rawBody | ConvertFrom-Json -ErrorAction Stop }
        catch { $parsedBody = $rawBody }
    }

    [PSCustomObject]@{
        StatusCode = $statusCode
        ElapsedMs  = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 1)
        Body       = $parsedBody
        RawBody    = $rawBody
    }
}
