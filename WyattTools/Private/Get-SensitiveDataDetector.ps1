<#
.SYNOPSIS
    Returns the detector table used by Find-SensitiveData.
.DESCRIPTION
    One place for every detection rule: FindingType, Category (PII or Secret), default Confidence,
    the value regex, an optional context regex that must appear within Window characters of the
    value, an optional validator name (see Test-SensitiveDataValidator), and scan hints. Rules
    contain patterns only, never sample values. A value regex may name a group 'val' to mark the
    part that is the sensitive value (otherwise the whole match is used).
.EXAMPLE
    Get-SensitiveDataDetector | Select-Object FindingType, Category, Confidence
.NOTES
    Name: Get-SensitiveDataDetector
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-21
    Prerequisites: None
    Properties: MaskMode is Digits, Secret, Header, or Literal (report SampleText instead of the
    match). Hint lists literals of which at least one must be on the line (cheap pre-filter).
    Requires is a literal that must have been seen earlier in the same file or part.
#>
function Get-SensitiveDataDetector {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    function Get-DetectorRule {
        [CmdletBinding()]
        [OutputType([PSCustomObject])]
        param(
            [string]$FindingType, [string]$Category, [string]$Confidence, [string]$Pattern,
            [string]$Context = '', [int]$Window = 0, [string]$Validator = '',
            [string]$MaskMode, [bool]$IgnoreCase = $false, [bool]$NeedsDigit = $false,
            [string[]]$Hint = @(), [string]$Requires = '', [string]$SampleText = ''
        )
        [PSCustomObject]@{
            FindingType = $FindingType; Category = $Category; Confidence = $Confidence
            Pattern = $Pattern; Context = $Context; Window = $Window; Validator = $Validator
            MaskMode = $MaskMode; IgnoreCase = $IgnoreCase; NeedsDigit = $NeedsDigit
            Hint = $Hint; Requires = $Requires; SampleText = $SampleText
        }
    }

    $q = [string][char]39   # single quote, kept out of the literals below for readability

    Get-DetectorRule SSN PII High '\b\d{3}-\d{2}-\d{4}\b' -Validator SsnRange -MaskMode Digits -NeedsDigit $true
    Get-DetectorRule SSN-Unformatted PII Medium '(?<![\d-])\d{9}(?![\d-])' -Context '\bssn|social security|soc sec' -Window 40 -Validator SsnRange -MaskMode Digits -NeedsDigit $true
    Get-DetectorRule CreditCard PII High '(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])' -Validator CardNumber -MaskMode Digits -NeedsDigit $true
    Get-DetectorRule BankRouting PII Medium '(?<![\d-])\d{9}(?![\d-])' -Context '\b(?:routing|aba|rtn)' -Window 40 -Validator AbaChecksum -MaskMode Digits -NeedsDigit $true
    Get-DetectorRule BankAccount PII Low '(?<![\d-])\d{6,17}(?![\d-])' -Context 'account\s*(?:no\b|number|#)|\bacct' -Window 40 -MaskMode Digits -NeedsDigit $true
    Get-DetectorRule DateOfBirth PII Medium '\b(?:\d{1,2}[/-]\d{1,2}[/-](?:\d{4}|\d{2})|\d{4}-\d{2}-\d{2})\b' -Context '\bdob\b|date of birth|birth\s?date' -Window 30 -MaskMode Digits -NeedsDigit $true
    Get-DetectorRule DriversLicense PII Low '\b(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{6,13}\b' -Context ("driver$q" + '?s?\s*lic|\bDL\s?(?:#|no)') -Window 30 -MaskMode Digits -NeedsDigit $true
    Get-DetectorRule Passport PII Low '\b(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{6,9}\b' -Context 'passport' -Window 30 -MaskMode Digits -NeedsDigit $true

    Get-DetectorRule PrivateKeyBlock Secret High '-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----' -MaskMode Header -Hint '-----BEGIN'
    Get-DetectorRule AwsAccessKey Secret High '\b(?:AKIA|ASIA)[0-9A-Z]{16}\b' -MaskMode Secret -Hint 'AKIA', 'ASIA'
    Get-DetectorRule AzureStorageConnStr Secret High 'AccountKey=(?<val>[A-Za-z0-9+/=]{80,})' -MaskMode Secret -Hint 'AccountKey='
    Get-DetectorRule GitHubToken Secret High '\b(?:gh[pousr]_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{70,})' -MaskMode Secret -Hint 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'
    Get-DetectorRule SlackToken Secret High '\bxox[abprs]-[A-Za-z0-9-]{10,}' -MaskMode Secret -Hint 'xox'
    Get-DetectorRule AnthropicKey Secret High '\bsk-ant-[A-Za-z0-9_-]{20,}' -MaskMode Secret -Hint 'sk-ant-'
    Get-DetectorRule OpenAIKey Secret High '\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}' -MaskMode Secret -Hint 'sk-'
    Get-DetectorRule Jwt Secret Medium '\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' -MaskMode Secret -Hint 'eyJ'
    Get-DetectorRule GenericApiKey Secret Medium ('(?:api[_-]?key|secret|token|client[_-]?secret)[' + $q + '"]?\s*[:=]\s*[' + $q + '"]?(?<val>[A-Za-z0-9_\-/+=]{16,})') -IgnoreCase $true -MaskMode Secret -Hint 'key', 'secret', 'token'
    Get-DetectorRule ConfigPassword Secret Medium ('\b(?:password|passwd|pwd)[' + $q + '"]?\s*[:=]\s*[' + $q + '"]?(?<val>[^\s' + $q + '";]{4,})') -Validator NotPlaceholder -IgnoreCase $true -MaskMode Secret -Hint 'pass', 'pwd'
    Get-DetectorRule ClixmlCredential Secret High '<SS N="Password">' -Requires 'System.Management.Automation.PSCredential' -MaskMode Literal -SampleText '<SS N="Password">(encrypted)' -Hint '<SS N="Password">'
    Get-DetectorRule RdpSavedPassword Secret High 'password 51:b:' -MaskMode Literal -SampleText 'password 51:b:(encrypted)' -Hint 'password 51:b:'
}
