# powershell-profile

Personal PowerShell profile for Windows PowerShell 5.1 and PowerShell 7. It loads the
WyattTools module (admin and M365 helper commands), an oh-my-posh prompt, and PSReadLine
tweaks including a filter that keeps likely secrets out of the history file.

## Quick start

1. Clone the repo.
2. Run `.\Bootstrap.ps1` in your normal shell and again in an admin shell. Use `-WhatIf` to preview.
3. Edit `WyattTools\config.psd1` (created from `config.example.psd1`).
4. Open a new shell.

`.\Bootstrap.ps1 -Export` saves your installed modules to `ps-modules.csv`, which Bootstrap uses on the next machine.

## Commands

- `tools` lists every WyattTools command, grouped by category.
- `tools -Detailed` adds descriptions.

Aliases are in parentheses. Every command has help: `Get-Help <command> -Examples`.

### Active Directory

- `Add-ADGroupUser` - Adds one user or a CSV of users to an AD group, skipping anyone already a direct member.
- `Remove-ADGroupUser` - Removes one user or a CSV of users from an AD group, only if they are a direct member.
- `Copy-ADGroupMembership` - Adds a target user to every group a source user is directly in (never removes anything).
- `Compare-ADGroupMembers` - Lists users in one group who are not in another (`-Not`, nested members included unless `-DirectOnly`).
- `Export-ADGroupToCSV` - Exports the members of one or more matching AD groups to a CSV.
- `Get-ADUserInfo` (`adinfo`) - Shows one user's account status, password dates, last logon, manager, and groups.
- `Get-ADUserDepartment` - Looks up the department for one user or a CSV of users.
- `Get-ADUsersByDept` - Exports all enabled users in a department (wildcards allowed) to a CSV.
- `Get-ADUserReport` - Exports users from one of the configured OUs (Active, Departed, CR, India) to a CSV.
- `Get-UserPasswordExpiration` (`Get-PwdExp`) - Shows when a user's password expires, honoring fine-grained password policies.
- `Get-StaleAccounts` - Lists enabled users and computers that haven't logged on in a set number of days (default 90).
- `Find-LockoutSource` - Finds which computer locked out an account by reading lockout events on the PDC.
- `Get-LapsPassword` (`laps`) - Copies a computer's LAPS admin password to the clipboard and clears it after 30 seconds.
- `Reset-LapsADPassword` (`lapsreset`) - Expires a computer's LAPS password so the device rotates it at its next policy check.
- `Start-ADSync` - Starts an Entra Connect delta sync on the sync server.
- `Get-ADSyncStatus` - Shows the Entra Connect scheduler state and the results of the most recent sync runs.

### Exchange / Microsoft 365

- `Connect-M365` - Connects to Microsoft Graph and Exchange Online, skipping anything already connected.
- `Show-InboxRuleDescription` (`ibr`, `gir`) - Lists a mailbox's inbox rules with plain-English descriptions.
- `Get-ExternalForwarding` (`extfwd`) - Finds mailboxes and inbox rules that forward mail outside the organization.
- `Get-GroupLicenseGap` - Lists members of a license group who don't have the license that group should grant (`-ListSkus` shows license names and free seats).

### Network

- `Test-Port` (`tp`) - Checks whether specific TCP ports are open on one or more hosts.
- `Get-CertExpiry` - Shows when a website's TLS certificate expires and flags ones expiring soon.
- `Get-PublicIP` - Returns this machine's public IP address.
- `Get-RemoteSystemInfo` - Shows OS, uptime, logged-on user, memory, and disk space for one or more computers.

### Utility

- `Show-WyattTools` (`tools`) - Lists all WyattTools commands and aliases.
- `Get-FileTail` (`tail`) - Shows the last lines of a file; `tail -f` keeps following it.
- `Invoke-ApiGet` (`get`) - Sends a GET request and returns the status code, timing, and parsed body.
- `Invoke-ApiPost` (`post`) - Sends a POST request with a JSON body and returns the status code, timing, and parsed body.
- `Convert-ToBase64` (`B64E`) - Base64-encodes a string.
- `grep` - Searches files or piped output for a pattern, grep-style (`-i -r -v -n -l -c`); use `rg` (ripgrep, installed by Bootstrap) for big folders.

### Git

- `add` - Stages files (`git add`, defaults to everything).
- `commit` - Commits with a message (`git commit -m`).
- `push` - Pushes a branch to origin (`git push origin <branch>`).
- `pull` - Pulls a branch from origin (`git pull origin <branch>`).

### Repo scripts

- `Bootstrap.ps1` - Installs the modules and tools this profile uses and adds the profile to both PowerShell versions.
- `Microsoft.PowerShell_profile.ps1` - Loads WyattTools, the prompt, and PSReadLine settings when a shell starts.

### Shortcuts

Aliases for commands that aren't WyattTools functions, defined in `WyattTools\Aliases.psd1`
and listed by `tools` under Shortcuts.

- `table` - `Format-Table`

## Adding a function

1. Drop a `.ps1` in `WyattTools\Public\<Category>\`.
2. Add the function name to `FunctionsToExport` in `WyattTools.psd1`.

## Adding an alias

- For a WyattTools function: put `Set-Alias` at the bottom of the function's file.
- For anything else (built-in cmdlets, external tools): add it under a category in `WyattTools\Aliases.psd1`.

Either way, also add the alias to `AliasesToExport` in `WyattTools.psd1`.

## sudo

Windows 11 has a built-in sudo. Enable it in Settings > System > Advanced > Enable sudo, or from an
elevated shell: `sudo config --enable normal`. Until then the profile defines a fallback `sudo`
function that opens an elevated window.

## Troubleshooting

- **winget fails with `0x8a15000f` ("Data required by the source is missing") in an admin
  account launched with `runas`:** the account has App Installer but not the winget source
  package. Run `Add-AppxPackage -Path 'https://cdn.winget.microsoft.com/cache/source.msix'`,
  then `winget source update`, then re-run `Bootstrap.ps1`. (`winget source reset --force`
  alone does not install the missing package.)
- **Prompt shows `SYSTEM@<host>` in a `runas /smartcard` shell:** runas can leave
  `USERNAME=SYSTEM` in the environment. The profile corrects it for the session; `whoami`
  shows the real account.

## Notes

`WyattTools\config.psd1` is gitignored because this repo is public. Never commit tenant names,
IDs, or secrets.
