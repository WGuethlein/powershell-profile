<#
.SYNOPSIS
    Builds a fixture tree for testing Find-SensitiveData, plus the expected-results CSV.
.DESCRIPTION
    Creates one small file per detector (positive cases) and a set of negative cases (checksum
    failures, invalid SSN ranges, placeholder passwords, excluded folders, a junction loop, a binary
    file, an oversized file) under -Path. Every fake value is assembled from fragments at run time,
    so no complete token, key, or SSN appears in this tracked file. Besides the fixtures it writes
    expected.csv (Path relative to the fixture folder, FindingType) and raw-values.lst, the list of
    raw fake values, so a tester can grep a scan report for unmasked values. raw-values.lst has a
    .lst extension on purpose: a .txt file would be scanned and flagged itself.
    Oversize case: big.log is a 60 MB file made with SetLength (instant, sparse), so it is skipped
    by the default -MaxFileSizeMB 50. Pass -SkipBigFile to leave it out and scan with a small
    -MaxFileSizeMB instead.
.PARAMETER Path
    Folder to build the fixture in. It is deleted and recreated if it already exists.
.PARAMETER SkipBigFile
    Do not create the 60 MB file.
.EXAMPLE
    pwsh -NoProfile -File .\tests\New-SensitiveDataFixture.ps1 -Path $env:TEMP\sdfix
.NOTES
    Name: New-SensitiveDataFixture
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-21
    Target: Both (Windows PowerShell 5.1 and PowerShell 7)
    Prerequisites: None. Writes only under -Path.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [Parameter()]
    [switch]$SkipBigFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$root = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
# Remove the junction itself first so the recursive delete never follows it.
$oldJunction = Join-Path $root ('loop' + [char]92 + 'a' + [char]92 + 'back')
if (Test-Path -LiteralPath $oldJunction) { [System.IO.Directory]::Delete($oldJunction) }
if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
$null = New-Item -ItemType Directory -Path $root

$expected = New-Object System.Collections.Generic.List[object]
$raw = New-Object System.Collections.Generic.List[string]

# Writes a fixture file; -Expect lists the FindingTypes that must be reported for it. -RawValues lists
# the raw fake values that must never appear in a report (RawValues).
function Add-Fixture {
    param([string]$Rel, [string[]]$Lines, [string[]]$Expect = @(), [string[]]$RawValues = @())
    $full = Join-Path $root $Rel
    $dir = Split-Path $full -Parent
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    [System.IO.File]::WriteAllText($full, (($Lines -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    foreach ($t in $Expect) { $expected.Add([PSCustomObject]@{ Path = $Rel; FindingType = $t }) }
    foreach ($r in $RawValues) { $raw.Add($r) }
}

# Writes an Office-style zip with the given parts (name -> xml text).
function Add-Zip {
    param([string]$Rel, [hashtable]$Parts, [string[]]$Expect = @(), [string[]]$RawValues = @())
    $full = Join-Path $root $Rel
    $dir = Split-Path $full -Parent
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $fs = [System.IO.File]::Create($full)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($name in $Parts.Keys) {
                $entry = $zip.CreateEntry($name)
                $sw = New-Object System.IO.StreamWriter($entry.Open(), (New-Object System.Text.UTF8Encoding($false)))
                try { $sw.Write($Parts[$name]) } finally { $sw.Dispose() }
            }
        }
        finally { $zip.Dispose() }
    }
    finally { $fs.Dispose() }
    foreach ($t in $Expect) { $expected.Add([PSCustomObject]@{ Path = $Rel; FindingType = $t }) }
    foreach ($r in $RawValues) { $raw.Add($r) }
}

# --- Fake values, assembled at run time --------------------------------------------------------
$ssn        = '123' + '-45-' + '6789'
$ssnPlain   = '123' + '45' + '6789'
$visa       = '4111' + ' 1111' + ' 1111' + ' 1111'
$visaBad    = '4111' + '1111' + '1111' + '1112'
$routing    = '0210' + '00021'
$routingBad = '1234' + '56789'
$account    = '1234' + '5678' + '901'
$dob        = '03/15/' + '1985'
$dl         = 'D' + '1234' + '567'
$passport   = 'X' + '1234' + '567'
$aws        = 'AKIA' + 'IOSFODNN7' + 'EXAMPLE'
$azureKey   = ('A' * 86) + '=='
$ghp        = 'ghp' + '_' + ('Ab1' * 12)
$slack      = 'xox' + 'b-' + '1234567890' + '-' + 'abcdefghij'
$anthropic  = 'sk' + '-ant-' + 'api03-' + ('Ab1' * 10)
$openai     = 'sk' + '-proj-' + ('Ab1' * 10)
$jwt        = 'eyJ' + 'hbGciOiJIUzI1NiJ9' + '.' + 'eyJ' + 'zdWIiOiJ0ZXN0In0' + '.' + 'abcdefghijklmnop'
$apiKey     = ('A1b2' + 'C3d4') * 3
$cfgPass    = 'Tr0ub4' + 'dor&3'
$rdpBlob    = 'ABCDEF' + '0123456789'
$pkHeader   = '-----BEGIN ' + 'RSA ' + 'PRIVATE KEY-----'

# --- Positive cases: PII ----------------------------------------------------------------------
Add-Fixture 'pii\ssn.txt' @("Applicant: $ssn") -Expect SSN -RawValues $ssn
Add-Fixture 'pii\ssn-unformatted.txt' @("Social security number $ssnPlain on file") -Expect 'SSN-Unformatted' -RawValues $ssnPlain
Add-Fixture 'pii\card.txt' @("Card: $visa exp 12/30") -Expect CreditCard -RawValues @($visa, ($visa -replace ' ', ''))
Add-Fixture 'pii\routing.txt' @("Routing number: $routing") -Expect BankRouting -RawValues $routing
Add-Fixture 'pii\account.txt' @("Account number: $account") -Expect BankAccount -RawValues $account
Add-Fixture 'pii\dob.txt' @("DOB: $dob") -Expect DateOfBirth -RawValues $dob
Add-Fixture 'pii\dl.txt' @("Driver's license no: $dl") -Expect DriversLicense -RawValues $dl
Add-Fixture 'pii\passport.txt' @("Passport: $passport") -Expect Passport -RawValues $passport

# --- Positive cases: secrets ------------------------------------------------------------------
Add-Fixture 'secret\privatekey.txt' @($pkHeader, ('A' * 40), ('-----END ' + 'RSA ' + 'PRIVATE KEY-----')) -Expect PrivateKeyBlock
Add-Fixture 'secret\aws.txt' @("key_id = $aws") -Expect AwsAccessKey -RawValues $aws
Add-Fixture 'secret\azure.txt' @("DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=$azureKey;EndpointSuffix=core.windows.net") -Expect AzureStorageConnStr -RawValues $azureKey
Add-Fixture 'secret\github.txt' @("value: $ghp") -Expect GitHubToken -RawValues $ghp
Add-Fixture 'secret\slack.txt' @("value: $slack") -Expect SlackToken -RawValues $slack
Add-Fixture 'secret\anthropic.txt' @("value: $anthropic") -Expect AnthropicKey -RawValues $anthropic
Add-Fixture 'secret\openai.txt' @("value: $openai") -Expect OpenAIKey -RawValues $openai
Add-Fixture 'secret\jwt.txt' @("value: $jwt") -Expect Jwt -RawValues $jwt
Add-Fixture 'secret\apikey.json' @('{"api_key": "' + $apiKey + '"}') -Expect GenericApiKey -RawValues $apiKey
Add-Fixture 'secret\config.ini' @('[db]', ('password=' + $cfgPass)) -Expect ConfigPassword -RawValues $cfgPass
Add-Fixture 'secret\cred.xml' @(
    '<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">',
    '  <Obj RefId="0">',
    ('    <TN RefId="0"><T>System.Management.Automation.' + 'PSCredential</T><T>System.Object</T></TN>'),
    '    <Props>',
    '      <S N="UserName">CONTOSO\demo</S>',
    '      <SS N="Password">deadbeefcafedeadbeefcafe</SS>',
    '    </Props>',
    '  </Obj>',
    '</Objs>') -Expect ClixmlCredential
Add-Fixture 'secret\conn.rdp' @('full address:s:host.example.test', ('password 51:b:' + $rdpBlob)) -Expect RdpSavedPassword -RawValues $rdpBlob

# --- Positive cases: mixed, extensionless, Office ---------------------------------------------
Add-Fixture 'multi\mixed.txt' @("first $ssn", "second $ssn", "key_id = $aws") -Expect SSN, AwsAccessKey
Add-Fixture 'misc\notes' @("Applicant: $ssn") -Expect SSN

$docx = '<w:document xmlns:w="urn:w"><w:body><w:tbl><w:tr><w:tc><w:p><w:r><w:t>SSN</w:t></w:r></w:p></w:tc>' +
    '<w:tc><w:p><w:r><w:t>123-45-</w:t></w:r><w:r><w:t>6789</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>'
Add-Zip 'office\table.docx' @{ 'word/document.xml' = $docx } -Expect SSN
$xlsx = '<sst xmlns="urn:x"><si><t>Visa</t></si><si><t>' + $visa + '</t></si></sst>'
Add-Zip 'office\cards.xlsx' @{ 'xl/sharedStrings.xml' = $xlsx } -Expect CreditCard
$pptx = '<p:sld xmlns:p="urn:p" xmlns:a="urn:a"><a:p><a:r><a:t>key_id = ' + $aws + '</a:t></a:r></a:p></p:sld>'
Add-Zip 'office\deck.pptx' @{ 'ppt/slides/slide1.xml' = $pptx } -Expect AwsAccessKey
Add-Zip 'office\clean.docx' @{ 'word/document.xml' = '<w:document xmlns:w="urn:w"><w:body><w:p><w:r><w:t>Quarterly newsletter draft</w:t></w:r></w:p></w:body></w:document>' }
Add-Zip 'office\ignored-part.docx' @{ 'word/settings.xml' = '<s>' + $ssn + '</s>' }

# --- Positive cases: name only ----------------------------------------------------------------
[System.IO.File]::WriteAllBytes((Join-Path (New-Item -ItemType Directory -Path (Join-Path $root 'keys') -Force).FullName 'cert.pfx'), [byte[]](1..64))
$expected.Add([PSCustomObject]@{ Path = 'keys\cert.pfx'; FindingType = 'KeyFile' })
Add-Fixture 'keys\vault.kdbx' @('placeholder') -Expect CredentialStore
Add-Fixture 'keys\id_rsa' @('placeholder') -Expect KeyFile
Add-Fixture 'home\.git-credentials' @('placeholder') -Expect KeyFile
Add-Fixture 'home\.aws\credentials' @('placeholder') -Expect KeyFile
Add-Fixture 'home\.netrc' @('placeholder') -Expect KeyFile

# --- Negative cases: nothing may be reported --------------------------------------------------
Add-Fixture 'negative\luhn-fail.txt' @("Card: $visaBad")
Add-Fixture 'negative\ssn-invalid-ranges.txt' @(
    ('900' + '-12-' + '3456'), ('000' + '-12-' + '3456'), ('666' + '-12-' + '3456'),
    ('123' + '-00-' + '4567'), ('123' + '-45-' + '0000'))
Add-Fixture 'negative\routing-bad-checksum.txt' @("Routing number: $routingBad")
Add-Fixture 'negative\nine-digits-no-context.txt' @("Order $ssnPlain shipped", "Reference $account")
Add-Fixture 'negative\date-no-context.txt' @("Meeting date: $dob")
Add-Fixture 'negative\placeholder-passwords.ps1' @(
    'password=$env:DB_PASS', 'password=${DB_PASS}', 'password=changeme', 'pwd=%DB_PASS%',
    'passwd=<your password>', 'password: ****', 'password=password', 'password=')
Add-Fixture 'negative\short-token.txt' @('token=abc', 'api_key=short')
Add-Fixture 'negative\sample.pub.txt' @('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ demo@host')
Add-Fixture 'keys\id_rsa.pub' @('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ demo@host')
Add-Fixture 'node_modules\pkg\skipped.txt' @("Applicant: $ssn")
Add-Fixture '.git\objects\skipped.txt' @("Applicant: $ssn")
Add-Fixture 'misc\data.bin' @("Applicant: $ssn")

# Extensionless file with a NUL byte in the first 8 KB: treated as binary and not scanned.
$binPath = Join-Path $root 'misc\binary-noext'
[System.IO.File]::WriteAllBytes($binPath, ([byte[]](0, 1, 2, 3) + [System.Text.Encoding]::ASCII.GetBytes("Applicant: $ssn")))

# Junction loop: loop\a\back points at loop. A scanner that follows it reports extra paths.
Add-Fixture 'loop\inside.txt' @("Applicant: $ssn") -Expect SSN
$null = New-Item -ItemType Directory -Path (Join-Path $root 'loop\a') -Force
$null = New-Item -ItemType Junction -Path (Join-Path $root 'loop\a\back') -Target (Join-Path $root 'loop')

# Oversize file (sparse; no data written): skipped under the default -MaxFileSizeMB 50.
if (-not $SkipBigFile) {
    $fs = [System.IO.File]::Create((Join-Path $root 'big.log'))
    try { $fs.SetLength(60MB) } finally { $fs.Dispose() }
}

# --- Expected results and raw values ----------------------------------------------------------
$expected | Sort-Object Path, FindingType | Export-Csv -LiteralPath (Join-Path $root 'expected.csv') -NoTypeInformation -Encoding UTF8
[System.IO.File]::WriteAllLines((Join-Path $root 'raw-values.lst'), [string[]]($raw | Sort-Object -Unique), (New-Object System.Text.UTF8Encoding($false)))

Write-Host "Fixture built in $root"
Write-Host "  Expected findings: $($expected.Count) (expected.csv)"
Write-Host "  Raw values:        $(@($raw | Sort-Object -Unique).Count) (raw-values.lst)"
