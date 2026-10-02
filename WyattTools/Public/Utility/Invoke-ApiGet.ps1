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
