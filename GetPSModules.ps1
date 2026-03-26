# Export-InstalledModules.ps1
# Exports all installed PowerShell modules (CurrentUser + AllUsers) to a CSV file.
# Run this on the source machine before migrating.

$outputPath = "$HOME\ps-modules.csv"

$scopes = @(
    "$HOME\Documents\PowerShell\Modules",          # CurrentUser (PS 7+)
    "$HOME\Documents\WindowsPowerShell\Modules",   # CurrentUser (PS 5.1)
    "C:\Users\admin-wguethlein\Documents\PowerShell\Modules",          # CurrentUser (PS 7+)
    "C:\Users\admin-wguethlein\Documents\WindowsPowerShell\Modules",   # CurrentUser (PS 5.1)
    "$env:ProgramFiles\PowerShell\Modules",         # AllUsers (PS 7+)
    "$env:ProgramFiles\WindowsPowerShell\Modules",  # AllUsers (PS 5.1)
    "$PSHOME\Modules"                               # System (skip — built-ins)
)

Get-InstalledModule |
    Select-Object -Property Name, Version, Repository |
    Export-Csv -Path $outputPath -NoTypeInformation

Write-Host "Exported to: $outputPath"