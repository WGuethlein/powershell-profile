<#
    WyattTools root module. Dot-sources Private\*.ps1, then Public\**\*.ps1 (the parent folder
    name is the command category), builds the index used by Show-WyattTools, and exports the
    public commands. File name = function name.
#>

$script:WyattModuleRoot = $PSScriptRoot
$script:WyattConfig     = $null
$script:WyattToolsIndex = New-Object 'System.Collections.Generic.List[hashtable]'

foreach ($file in @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -File -ErrorAction SilentlyContinue)) {
    try { . $file.FullName }
    catch { Write-Warning "WyattTools: failed to load $($file.FullName): $($_.Exception.Message)" }
}

foreach ($file in @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue)) {
    try {
        . $file.FullName
        $script:WyattToolsIndex.Add(@{
            Name     = $file.BaseName
            Category = $file.Directory.Name
            Aliases  = @()
        })
    }
    catch { Write-Warning "WyattTools: failed to load $($file.FullName): $($_.Exception.Message)" }
}

# Attach aliases (defined via Set-Alias in the function files) to the index.
$publicNames = @($script:WyattToolsIndex | ForEach-Object { $_.Name })
$aliasNames  = New-Object 'System.Collections.Generic.List[string]'
foreach ($alias in @(Get-Alias | Where-Object { $publicNames -contains $_.Definition })) {
    $entry = $script:WyattToolsIndex | Where-Object { $_.Name -eq $alias.Definition } | Select-Object -First 1
    $entry.Aliases += $alias.Name
    $aliasNames.Add($alias.Name)
}

Export-ModuleMember -Function $publicNames -Alias $aliasNames.ToArray()
