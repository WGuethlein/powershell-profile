<#
.SYNOPSIS
    Copies a computer's Windows LAPS local admin password (AD-backed) to the clipboard.
.DESCRIPTION
    Wrapper around Get-LapsADPassword from the built-in LAPS module. The password is retrieved
    as a SecureString and is never printed; it is converted to plain text only to place it on
    the clipboard. The account name, last update and expiration time are shown on screen.
    After -ClearAfter seconds a hidden helper clears the clipboard, but only if it still holds
    this password (it compares a SHA256 hash, so the password itself is never passed to it).
.PARAMETER ComputerName
    AD computer name. Accepts pipeline input (including objects from Get-ADComputer).
.PARAMETER ClearAfter
    Seconds before the clipboard is cleared. Default 30. Use 0 to leave it on the clipboard.
.EXAMPLE
    Get-LapsPassword PC1234
.EXAMPLE
    laps PC1234 -ClearAfter 0
.EXAMPLE
    Get-ADComputer 'PC-0423' | Get-LapsPassword -ClearAfter 120
    Takes the computer from the pipeline and keeps the password on the clipboard for two minutes.
.EXAMPLE
    laps PC-0423 | Select-Object ComputerName, Account, ExpirationTimestamp
    Shows which local account the password belongs to and when it expires (the password itself is never printed).
.NOTES
    Name: Get-LapsPassword
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: Windows LAPS module (built into Windows), read/decrypt rights on the computer object.
    Windows clipboard history (Win+V), if enabled, may still retain the copied value.
#>
function Get-LapsPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Name', 'Identity', 'Computer')]
        [string]$ComputerName,

        [ValidateRange(0, 3600)]
        [int]$ClearAfter = 30
    )

    begin {
        Assert-Module -Name LAPS
    }

    process {
        try {
            # Without -AsPlainText the Password property is a SecureString.
            $entry = Get-LapsADPassword -Identity $ComputerName -ErrorAction Stop | Select-Object -First 1
        }
        catch {
            Write-Error "Failed to query LAPS for '$ComputerName': $($_.Exception.Message)"
            return
        }

        if ($null -eq $entry) {
            Write-Warning "No LAPS password found for '$ComputerName'."
            return
        }
        if ($null -eq $entry.Password) {
            Write-Warning "LAPS password for '$ComputerName' is not readable (DecryptionStatus: $($entry.DecryptionStatus), AuthorizedDecryptor: $($entry.AuthorizedDecryptor))."
            return
        }

        $plain = [System.Net.NetworkCredential]::new('', $entry.Password).Password
        Set-Clipboard -Value $plain

        if ($ClearAfter -gt 0) {
            # Hand the helper only a hash of the password, never the password itself.
            $sha  = [System.Security.Cryptography.SHA256]::Create()
            $hash = [System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plain))).Replace('-', '')
            $sha.Dispose()

            $clearScript = @"
Start-Sleep -Seconds $ClearAfter
`$c = Get-Clipboard -Raw
if (`$c) {
    `$s = [System.Security.Cryptography.SHA256]::Create()
    `$h = [System.BitConverter]::ToString(`$s.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(`$c))).Replace('-', '')
    if (`$h -eq '$hash') { Set-Clipboard -Value ' ' }
}
"@
            $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($clearScript))
            # Use the current host exe: powershell.exe launched from pwsh inherits pwsh's
            # PSModulePath and fails to load its own clipboard cmdlets.
            Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList '-NoProfile', '-WindowStyle', 'Hidden', '-EncodedCommand', $encoded -WindowStyle Hidden
        }
        $plain = $null

        $clearNote = 'stays on clipboard'
        if ($ClearAfter -gt 0) { $clearNote = "clipboard clears in $ClearAfter s" }
        Write-Host "LAPS password for $($entry.ComputerName) copied ($clearNote)." -ForegroundColor Green

        [PSCustomObject]@{
            ComputerName        = $entry.ComputerName
            Account             = $entry.Account
            PasswordUpdateTime  = $entry.PasswordUpdateTime
            ExpirationTimestamp = $entry.ExpirationTimestamp
            Source              = $entry.Source
        }
    }
}

Set-Alias -Name laps -Value Get-LapsPassword
