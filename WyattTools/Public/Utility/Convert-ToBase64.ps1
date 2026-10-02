<#
.SYNOPSIS
    Base64-encodes a string (UTF-8).
.DESCRIPTION
    Converts the input text to UTF-8 bytes and returns the Base64 string. Accepts pipeline input.
.PARAMETER Text
    The text to encode.
.EXAMPLE
    Convert-ToBase64 'hello'
.EXAMPLE
    'hello' | B64E
.NOTES
    Name: Convert-ToBase64
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None
#>
function Convert-ToBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$Text
    )

    process {
        [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text))
    }
}

Set-Alias -Name B64E -Value Convert-ToBase64
