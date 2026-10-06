<#
.SYNOPSIS
    Sends a GET request and returns status code, timing, and parsed body.
.DESCRIPTION
    Quick interactive endpoint test. Returns a PSCustomObject with StatusCode, ElapsedMs, Body
    (parsed JSON when possible) and RawBody. Non-2xx responses are returned, not thrown.
.PARAMETER Uri
    Full target URL.
.PARAMETER Headers
    Optional extra headers, for example @{ Authorization = "Bearer ..." }.
.EXAMPLE
    get https://api.example.com/users/5
.EXAMPLE
    get https://api.example.com/users/5 @{ Authorization = 'Bearer <token>' }
    Sends a GET with an Authorization header (Headers is the second positional parameter).
.EXAMPLE
    (get https://api.example.com/users).Body | Select-Object -First 5
    Returns only the parsed body of the response and shows its first five items.
.EXAMPLE
    $r = get https://api.example.com/health; if ($r.StatusCode -ne 200) { "Unhealthy: $($r.StatusCode) in $($r.ElapsedMs) ms" }
    Checks the status code and response time of a health endpoint.
.NOTES
    Name: Invoke-ApiGet
    Version: 2.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None
#>
function Invoke-ApiGet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Uri,

        [Parameter(Position = 1)]
        [hashtable]$Headers
    )

    Invoke-ApiRequest -Method GET -Uri $Uri -Headers $Headers
}

Set-Alias -Name get -Value Invoke-ApiGet
