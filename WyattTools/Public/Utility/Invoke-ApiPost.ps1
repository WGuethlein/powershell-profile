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
