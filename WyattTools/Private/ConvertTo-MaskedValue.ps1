<#
.SYNOPSIS
    Masks a sensitive value so it can be shown in a report without revealing it.
.DESCRIPTION
    Digit mode (PII) replaces every letter and digit except the last four with an asterisk and keeps
    separators, for example ***-**-1234. Secret mode keeps the first four and last four characters
    when the value is 20 or longer, otherwise only the first two. Header mode returns the text
    unchanged and is for fixed public markers such as a private key header line.
.PARAMETER Value
    The raw text to mask.
.PARAMETER Mode
    Digits, Secret, or Header.
.EXAMPLE
    ConvertTo-MaskedValue -Value 'abcdefghijklmnopqrstuvwxyz' -Mode Secret
    Returns abcd****************wxyz.
.NOTES
    Name: ConvertTo-MaskedValue
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-21
    Prerequisites: None
#>
function ConvertTo-MaskedValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory)]
        [ValidateSet('Digits', 'Secret', 'Header')]
        [string]$Mode
    )

    if ([string]::IsNullOrEmpty($Value)) { return '' }

    switch ($Mode) {
        'Header' { return $Value }
        'Digits' {
            $chars = $Value.ToCharArray()
            $alnum = 0
            foreach ($c in $chars) { if ([char]::IsLetterOrDigit($c)) { $alnum++ } }
            $keepFrom = $alnum - 4
            if ($keepFrom -lt 0) { $keepFrom = $alnum }
            $seen = 0
            for ($i = 0; $i -lt $chars.Length; $i++) {
                if ([char]::IsLetterOrDigit($chars[$i])) {
                    if ($seen -lt $keepFrom) { $chars[$i] = [char]'*' }
                    $seen++
                }
            }
            return (New-Object string (, $chars))
        }
        'Secret' {
            $len = $Value.Length
            if ($len -ge 20) {
                $stars = [Math]::Min($len - 8, 16)
                return $Value.Substring(0, 4) + ('*' * $stars) + $Value.Substring($len - 4)
            }
            $keep = [Math]::Min(2, $len)
            return $Value.Substring(0, $keep) + ('*' * [Math]::Max($len - $keep, 0))
        }
    }
}
