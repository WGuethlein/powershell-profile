$ScriptFolder = Join-Path $PSScriptRoot "Functions"

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
Oh-My-Posh init pwsh --config "$PSScriptRoot\OMP\my.omp.json" | Invoke-Expression
Enable-Poshtooltips
Write-Host

Set-Alias -Name tail -Value Tail-File

# Git shorthand functions
# Wraps common git operations with shorter syntax.

function push {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Branch
    )
    git push origin $Branch
}

function pull {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Branch
    )
    git pull origin $Branch
}

function commit {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message
    )
    git commit -m $Message
}

function add {
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$Path = "."
    )
    git add $Path
}