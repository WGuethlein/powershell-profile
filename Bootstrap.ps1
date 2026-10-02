<#
.SYNOPSIS
    Sets up (or exports the module list of) this PowerShell profile on a machine.
.DESCRIPTION
    Default action (-Install): installs PowerShell modules for CurrentUser, winget packages
    (oh-my-posh, zoxide, fzf), checks RSAT, creates WyattTools\config.psd1 from the example,
    and writes profile stubs for both Windows PowerShell 5.1 and PowerShell 7.
    -Export writes the installed module list (Name, Version, Repository) to a CSV.
    Safe to re-run. Use -WhatIf to preview.
.NOTES
    Name:    Bootstrap.ps1
    Version: 1.0
    Author:  WGuethlein
    Date:    2026-10-02
    Requires: PowerShell 5.1+, internet access for installs. Run once in a normal shell
              and, for RSAT, follow the printed hint in an elevated shell.
.EXAMPLE
    .\Bootstrap.ps1 -WhatIf
.EXAMPLE
    .\Bootstrap.ps1 -Export
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Export the installed module list instead of installing.
    [switch]$Export,

    # Install everything (default action; present for explicitness).
    [switch]$Install,

    # CSV used for -Export output and as the module source for install.
    [ValidateNotNullOrEmpty()]
    [string]$ModuleListPath = (Join-Path $PSScriptRoot 'ps-modules.csv')
)

# --- Configurable defaults ---
$defaultModules = @('ExchangeOnlineManagement', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Terminal-Icons', 'PSFzf')
$wingetPackages = @('JanDeDobbeleer.OhMyPosh', 'ajeetdsouza.zoxide', 'junegunn.fzf', 'Insecure.Nmap')

$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param([string]$Step, [ValidateSet('Done', 'Skipped', 'Failed')][string]$Status, [string]$Detail = '')
    $color = @{ Done = 'Green'; Skipped = 'Yellow'; Failed = 'Red' }[$Status]
    Write-Host ("[{0}] {1} {2}" -f $Status, $Step, $Detail) -ForegroundColor $color
    $results.Add([pscustomobject]@{ Step = $Step; Status = $Status })
}

# 5.1 may default to older TLS; PSGallery needs 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if ($Export) {
    try {
        if ($PSCmdlet.ShouldProcess($ModuleListPath, 'Export installed module list')) {
            Get-InstalledModule | Select-Object -Property Name, Version, Repository |
                Export-Csv -Path $ModuleListPath -NoTypeInformation
            Add-Result 'Export modules' 'Done' $ModuleListPath
        }
    }
    catch { Add-Result 'Export modules' 'Failed' $_.Exception.Message }
    return
}

# a. PowerShell modules
$moduleNames = $defaultModules
if (Test-Path $ModuleListPath) {
    try { $moduleNames = @(Import-Csv $ModuleListPath | ForEach-Object { $_.Name }) }
    catch { Write-Warning "Could not read $ModuleListPath, using defaults: $($_.Exception.Message)" }
}
foreach ($name in $moduleNames) {
    try {
        if (Get-Module -ListAvailable -Name $name) { Add-Result "Module $name" 'Skipped' 'already installed'; continue }
        if ($PSCmdlet.ShouldProcess($name, 'Install-Module (CurrentUser)')) {
            Install-Module -Name $name -Scope CurrentUser -Repository PSGallery -ErrorAction Stop
            Add-Result "Module $name" 'Done'
        }
    }
    catch { Add-Result "Module $name" 'Failed' $_.Exception.Message }
}

# b. winget packages (no --accept flags: the user sees and answers the prompts)
if ([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
    # winget depends on per-user app registrations that the SYSTEM account doesn't have.
    Add-Result 'winget packages' 'Skipped' 'running as SYSTEM (winget unsupported); run Bootstrap as your admin user instead'
}
elseif (Get-Command winget -ErrorAction SilentlyContinue) {
    # 0x8A15000F (-1978335217) = "Data required by the source is missing": this account's winget
    # source is uninitialized/corrupt. Every package would fail the same way, so stop at the first one.
    $sourceBrokenCode = -1978335217
    $sourceBroken = $false
    foreach ($id in $wingetPackages) {
        if ($sourceBroken) { Add-Result "winget $id" 'Skipped' 'winget source broken (see hint above)'; continue }
        try {
            winget list --id $id -e --source winget 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { Add-Result "winget $id" 'Skipped' 'already installed'; continue }
            if ($LASTEXITCODE -eq $sourceBrokenCode) { $sourceBroken = $true }
            elseif ($PSCmdlet.ShouldProcess($id, 'winget install')) {
                winget install --id $id -e --source winget
                if ($LASTEXITCODE -eq 0) { Add-Result "winget $id" 'Done' }
                elseif ($LASTEXITCODE -eq $sourceBrokenCode) { $sourceBroken = $true }
                else { Add-Result "winget $id" 'Failed' "exit code $LASTEXITCODE" }
            }
            if ($sourceBroken) {
                Add-Result "winget $id" 'Failed' 'winget source data missing (0x8A15000F)'
                Write-Host 'winget source is broken for this account. Fix, then re-run Bootstrap:' -ForegroundColor Yellow
                Write-Host '  1. winget source reset --force   (elevated)' -ForegroundColor Yellow
                Write-Host "  2. If that doesn't help, the source package is missing for this account (common for runas-only admin accounts):" -ForegroundColor Yellow
                Write-Host "     Add-AppxPackage -Path 'https://cdn.winget.microsoft.com/cache/source.msix'; winget source update" -ForegroundColor Yellow
            }
        }
        catch { Add-Result "winget $id" 'Failed' $_.Exception.Message }
    }
    Write-Host 'Hint: install a Nerd Font for prompt icons with: oh-my-posh font install' -ForegroundColor Cyan
}
else { Add-Result 'winget packages' 'Skipped' 'winget not found' }

# c. RSAT (needs elevation; only print the command)
if (Get-Module -ListAvailable -Name ActiveDirectory) { Add-Result 'RSAT ActiveDirectory' 'Skipped' 'already installed' }
else {
    Add-Result 'RSAT ActiveDirectory' 'Skipped' 'missing; run this in an elevated shell:'
    Write-Host '  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -ForegroundColor Cyan
}

# d. WyattTools config (gitignored; copied from the example)
$configPath = Join-Path $PSScriptRoot 'WyattTools\config.psd1'
$examplePath = Join-Path $PSScriptRoot 'WyattTools\config.example.psd1'
try {
    if (Test-Path $configPath) { Add-Result 'WyattTools config' 'Skipped' 'config.psd1 exists' }
    elseif (-not (Test-Path $examplePath)) { Add-Result 'WyattTools config' 'Skipped' 'config.example.psd1 not found' }
    elseif ($PSCmdlet.ShouldProcess($configPath, 'Copy from config.example.psd1')) {
        Copy-Item -Path $examplePath -Destination $configPath
        Add-Result 'WyattTools config' 'Done' "created; edit it: $configPath"
    }
}
catch { Add-Result 'WyattTools config' 'Failed' $_.Exception.Message }

# e. Profile stubs for both editions (append only, never overwrite)
$docs = [Environment]::GetFolderPath('MyDocuments')   # honors OneDrive folder redirection
$stubLine = '. "' + (Join-Path $PSScriptRoot 'Microsoft.PowerShell_profile.ps1') + '"'
foreach ($folder in @('PowerShell', 'WindowsPowerShell')) {
    $stubPath = Join-Path $docs "$folder\Microsoft.PowerShell_profile.ps1"
    try {
        if ((Test-Path $stubPath) -and (Select-String -Path $stubPath -SimpleMatch -Pattern $stubLine -Quiet)) {
            Add-Result "Profile stub $folder" 'Skipped' 'already present'
            continue
        }
        if ($PSCmdlet.ShouldProcess($stubPath, 'Append profile stub')) {
            $dir = Split-Path $stubPath
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Add-Content -Path $stubPath -Value $stubLine
            Add-Result "Profile stub $folder" 'Done' $stubPath
        }
    }
    catch { Add-Result "Profile stub $folder" 'Failed' $_.Exception.Message }
}

# Summary
Write-Host "`nSummary" -ForegroundColor Cyan
$results | Group-Object Status | ForEach-Object { Write-Host ("  {0}: {1}" -f $_.Name, $_.Count) }
$results | Where-Object Status -eq 'Failed' | ForEach-Object { Write-Host "  FAILED: $($_.Step)" -ForegroundColor Red }
