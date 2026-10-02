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

## Adding a function

1. Drop a `.ps1` in `WyattTools\Public\<Category>\`.
2. Add the function name to `FunctionsToExport` in `WyattTools.psd1`.

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
