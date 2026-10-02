# Microsoft.PowerShell_profile.ps1
# Daily profile for Windows PowerShell 5.1 and PowerShell 7. Loads the WyattTools module,
# prompt (oh-my-posh), PSReadLine tweaks, history secret filter, and optional PSFzf.
# Author: WGuethlein   Date: 2026-10-02
# Usage: dot-sourced from the real $PROFILE stub written by Bootstrap.ps1.

$PSDefaultParameterValues['Connect-ExchangeOnline:ShowBanner'] = $false

# runas /smartcard can leave USERNAME=SYSTEM in the environment even though the session runs as
# the target account. Correct it (this process only) so oh-my-posh and scripts show the real user.
$tokenUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\')[-1]
if ($env:USERNAME -ne $tokenUser) { $env:USERNAME = $tokenUser }
Remove-Variable tokenUser

# --- WyattTools module (personal commands) ---
try {
    Import-Module (Join-Path $PSScriptRoot 'WyattTools\WyattTools.psd1') -ErrorAction Stop
    if (Get-Command Show-WyattTools -ErrorAction SilentlyContinue) { Show-WyattTools }
}
catch {
    Write-Warning "WyattTools not loaded: $($_.Exception.Message)"
}

# --- Optional modules / prompt ---
# Startup speed: try/catch Import-Module beats Get-Module -ListAvailable (full module scan), and
# -CommandType Application keeps Get-Command from searching every module for a missing exe.
try { Import-Module Terminal-Icons -ErrorAction Stop } catch { Write-Verbose 'Terminal-Icons not installed.' }

# UTF-8 console so prompt glyphs render. Some native tools (e.g. winget) switch the console to
# code page 437, which turns the glyphs into '?' and can confuse PSReadLine's redraw.
try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
    [Console]::InputEncoding  = New-Object System.Text.UTF8Encoding $false
}
catch { Write-Verbose "Console encoding not set: $($_.Exception.Message)" }

if (Get-Command oh-my-posh -CommandType Application -ErrorAction SilentlyContinue) {
    $ompShell = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' }
    oh-my-posh init $ompShell --config "$PSScriptRoot\OMP\my.omp.json" | Invoke-Expression
    if (Get-Command Enable-PoshTooltips -ErrorAction SilentlyContinue) { Enable-PoshTooltips }

    # Wrap the oh-my-posh prompt to restore UTF-8 if a command changed the code page.
    # $? must be read first (any statement overwrites it); oh-my-posh accepts it through
    # $global:NVS_ORIGINAL_LASTEXECUTIONSTATUS, so the exit-code segment stays correct.
    $global:WyattOmpPrompt = $function:prompt
    function global:prompt {
        $global:NVS_ORIGINAL_LASTEXECUTIONSTATUS = $?
        try {
            if ([Console]::OutputEncoding.CodePage -ne 65001) { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false }
            if ([Console]::InputEncoding.CodePage -ne 65001)  { [Console]::InputEncoding  = New-Object System.Text.UTF8Encoding $false }
        }
        catch { }
        & $global:WyattOmpPrompt
    }
}

# --- PSReadLine ---
if (Get-Module PSReadLine) {
    Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
    Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward

    # Prediction features need PSReadLine 2.2.0+ (not available in the 2.0.0 shipped with 5.1).
    # Inline view from history only: ListView redraws several lines on every keystroke, which
    # made held keys (e.g. backspace) lag and freeze. Press F2 to switch to the list view.
    if ((Get-Module PSReadLine).Version -ge [version]'2.2.0') {
        try {
            Set-PSReadLineOption -PredictionSource History -ErrorAction Stop
            Set-PSReadLineOption -PredictionViewStyle InlineView -ErrorAction Stop
        }
        catch { Write-Verbose "Prediction not configured: $($_.Exception.Message)" }
    }

    # Keep lines that look like they contain secrets out of the history file.
    # Patterns (case-insensitive): bearer tokens, -Password / -ClientSecret / -AccessToken
    # parameters, ConvertTo-SecureString (plaintext conversions), apikey / api_key, Authorization headers.
    $secretPattern = 'Bearer\s|-Password|-ClientSecret|-AccessToken|ConvertTo-SecureString|apikey|api_key|Authorization'
    $hasHistoryEnum = $null -ne ('Microsoft.PowerShell.AddToHistoryOption' -as [type])
    $hasDefaultOption = $null -ne ([Microsoft.PowerShell.PSConsoleReadLine].GetMethod('GetDefaultAddToHistoryOption'))
    try {
        Set-PSReadLineOption -AddToHistoryHandler ({
            param([string]$line)
            if ($line -match $secretPattern) {
                if ($hasHistoryEnum) { return [Microsoft.PowerShell.AddToHistoryOption]::MemoryOnly }
                return $false
            }
            if ($hasDefaultOption) {
                return [Microsoft.PowerShell.PSConsoleReadLine]::GetDefaultAddToHistoryOption($line)
            }
            return $true
        }).GetNewClosure()
    }
    catch { Write-Warning "History filter not set: $($_.Exception.Message)" }
}

# --- PSFzf (silent when absent) ---
try {
    Import-Module PSFzf -ErrorAction Stop
    Set-PsFzfOption -PSReadlineChordProvider 'Ctrl+t' -PSReadlineChordReverseHistory 'Ctrl+r'
}
catch { Write-Verbose 'PSFzf not installed.' }

# --- sudo fallback (only when the Windows built-in sudo.exe is not available) ---
if ($null -eq (Get-Command sudo.exe -CommandType Application -ErrorAction SilentlyContinue)) {
    function sudo {
        # Runs the given command elevated in a new window; no args opens an elevated shell.
        $hostExe = (Get-Process -Id $PID).Path
        if ($args.Count -eq 0) { Start-Process $hostExe -Verb RunAs; return }
        Start-Process $hostExe -Verb RunAs -ArgumentList '-NoExit', '-Command', ($args -join ' ')
    }
}
