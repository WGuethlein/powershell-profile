<#
.SYNOPSIS
    Sends a POST request (JSON body) and returns status code, timing, and parsed body.
.DESCRIPTION
    Quick interactive endpoint test. Returns a PSCustomObject with StatusCode, ElapsedMs, Body
    (parsed JSON when possible) and RawBody. Non-2xx responses are returned, not thrown.
.PARAMETER Uri
    Full target URL.
.PARAMETER Body
    Raw JSON body string.
.PARAMETER Headers
    Optional extra headers, for example @{ Authorization = "Bearer ..." }.
.EXAMPLE
    post https://api.example.com/users '{"name":"Ada"}'
.EXAMPLE
    post https://api.example.com/users '{"name":"Ada"}' @{ Authorization = 'Bearer <token>' }
    Sends a JSON body with an Authorization header (Headers is the third positional parameter).
.EXAMPLE
    $body = @{ name = 'Ada'; roles = @('admin','dev') } | ConvertTo-Json -Compress; post https://api.example.com/users $body
    Builds the JSON body from a hashtable first, then posts it.
.EXAMPLE
    Invoke-ApiPost -Uri https://api.example.com/orders -Body '{"id":7}' -Headers @{ 'X-Api-Key' = '<key>' } | Select-Object StatusCode, ElapsedMs, RawBody
    Uses named parameters and a custom header and shows the status, timing, and unparsed response.
.NOTES
    Name: Invoke-ApiPost
    Version: 2.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None
#>
function Invoke-ApiPost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Uri,

        [Parameter(Position = 1)]
        [string]$Body,

        [Parameter(Position = 2)]
        [hashtable]$Headers
    )

    Invoke-ApiRequest -Method POST -Uri $Uri -Body $Body -Headers $Headers
}

Set-Alias -Name post -Value Invoke-ApiPost
