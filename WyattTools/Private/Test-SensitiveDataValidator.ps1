<#
.SYNOPSIS
    Pure validation checks that confirm or reject a regex hit from the sensitive-data scanner.
.DESCRIPTION
    Holds the Luhn checksum, ABA routing checksum, SSN range rules, card brand/length rules, and the
    placeholder-password filter. Each check takes the matched text and returns $true when the hit
    looks real and should be reported. The function has no state and touches no files, so it is easy
    to test and can be copied into a runspace as text.
.PARAMETER Name
    Which check to run: Luhn, AbaChecksum, SsnRange, CardNumber, or NotPlaceholder.
.PARAMETER Value
    The matched text. Digit checks ignore any non-digit characters (spaces, dashes).
.EXAMPLE
    Test-SensitiveDataValidator -Name NotPlaceholder -Value 'changeme'
    Returns $false: a well-known placeholder is not treated as a real password.
.NOTES
    Name: Test-SensitiveDataValidator
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-21
    Prerequisites: None
#>
function Test-SensitiveDataValidator {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Luhn', 'AbaChecksum', 'SsnRange', 'CardNumber', 'NotPlaceholder')]
        [string]$Name,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    switch ($Name) {
        'Luhn' {
            $digits = $Value -replace '\D', ''
            if ($digits.Length -lt 2) { return $false }
            $sum = 0
            $double = $false
            for ($i = $digits.Length - 1; $i -ge 0; $i--) {
                $n = [int][char]$digits[$i] - 48
                if ($double) {
                    $n = $n * 2
                    if ($n -gt 9) { $n = $n - 9 }
                }
                $sum += $n
                $double = -not $double
            }
            return (($sum % 10) -eq 0)
        }
        'AbaChecksum' {
            $digits = $Value -replace '\D', ''
            if ($digits.Length -ne 9) { return $false }
            $d = @(foreach ($c in $digits.ToCharArray()) { [int][char]$c - 48 })
            $sum = 3 * ($d[0] + $d[3] + $d[6]) + 7 * ($d[1] + $d[4] + $d[7]) + ($d[2] + $d[5] + $d[8])
            return ($sum -ne 0 -and ($sum % 10) -eq 0)
        }
        'SsnRange' {
            $digits = $Value -replace '\D', ''
            if ($digits.Length -ne 9) { return $false }
            $area = [int]$digits.Substring(0, 3)
            if ($area -eq 0 -or $area -eq 666 -or $area -ge 900) { return $false }
            if ($digits.Substring(3, 2) -eq '00') { return $false }
            if ($digits.Substring(5, 4) -eq '0000') { return $false }
            return $true
        }
        'CardNumber' {
            $digits = $Value -replace '\D', ''
            if ($digits.Length -lt 13 -or $digits.Length -gt 19) { return $false }
            $brand = '^(?:4(?:\d{12}|\d{15}|\d{18})' +
                '|5[1-5]\d{14}' +
                '|2(?:22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720)\d{12}' +
                '|3[47]\d{13}' +
                '|(?:6011|65\d\d|64[4-9]\d)\d{12,15})$'
            if ($digits -notmatch $brand) { return $false }
            return (Test-SensitiveDataValidator -Name Luhn -Value $digits)
        }
        'NotPlaceholder' {
            $v = $Value.Trim().Trim([char[]]@([char]39, [char]34))
            if ($v.Length -eq 0) { return $false }
            if ($v.StartsWith('$') -or $v.Contains('${') -or $v.Contains('{{')) { return $false }
            if ($v -match '^%[^%]+%$') { return $false }
            if ($v.StartsWith('<')) { return $false }
            if ($v -match '^\*+$') { return $false }
            if ($v -ieq 'changeme' -or $v -ieq 'password') { return $false }
            return $true
        }
    }
}
