$ScriptFolder = Join-Path $PSScriptRoot "Functions"

Write-Host "Script Folder Path: $ScriptFolder" -ForegroundColor Cyan
Write-Host "Folder Exists: $(Test-Path $ScriptFolder)" -ForegroundColor Cyan

if (Test-Path $ScriptFolder) {
    Get-ChildItem -Path $ScriptFolder -Filter "*.ps1" -File | ForEach-Object {
        try {
            Write-Host "Loading: $($_.Name)" -ForegroundColor Green
            . $_.FullName
        }
        catch {
            Write-Warning "Failed to load script: $($_.Name) - $($_.Exception.Message)"
        }
    }
}
else {
    Write-Warning "Functions folder not found at: $ScriptFolder"
}

Import-Module Terminal-Icons
#Oh-My-Posh init pwsh --config "$PSScriptRoot\OMP\my.omp.json" | Invoke-Expression
#Enable-Poshtooltips
Write-Host