$ScriptFolder = ".\Functions"
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

Import-Module Terminal-Icons

Oh-My-Posh init pwsh --config $PSSCRIPTROOT\OMP\my.omp.json | Invoke-Expression
Enable-Poshtooltips
Write-Host