<#
.SYNOPSIS
    Lists the commands available in the WyattTools module.
.DESCRIPTION
    Default mode prints a compact, color-coded list grouped by category (the parent folder of
    each command), followed by the aliases. It reads an in-memory index built at module load,
    so it is fast. -Detailed adds the synopsis and first example per command via Get-Help.
.PARAMETER Detailed
    Show the synopsis and first example for every command.
.PARAMETER Width
    Wrap width in characters. Default 0 uses the current console width. Lists wrap between
    command names (never mid-name), with continuation lines indented under the first name.
.EXAMPLE
    tools
.EXAMPLE
    Show-WyattTools -Detailed
.NOTES
    Name: Show-WyattTools
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None
#>
function Show-WyattTools {
    [CmdletBinding()]
    param(
        [switch]$Detailed,

        # Wrap width in characters; 0 = current console width.
        [ValidateRange(0, 1000)]
        [int]$Width = 0
    )

    $groups = $script:WyattToolsIndex | Group-Object { $_.Category } | Sort-Object Name
    $pad = ($groups | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
    if ($pad -lt 'Aliases'.Length) { $pad = 'Aliases'.Length }

    Write-Host "WyattTools" -ForegroundColor Magenta

    if (-not $Detailed) {
        # Console width; falls back to 120 when there is no real console (redirected/ISE).
        $width = $Width
        if ($width -eq 0) {
            $width = 120
            try { if ($Host.UI.RawUI.WindowSize.Width -gt 0) { $width = $Host.UI.RawUI.WindowSize.Width } } catch { }
        }

        # Writes "Label : a, b, c" wrapping at item boundaries; continuation lines are indented
        # under the first item so command names are never split mid-word.
        $writeWrapped = {
            param([string]$Label, [string[]]$Items, [string]$LabelColor, [string]$ItemColor)
            $prefix = $Label.PadRight($pad) + ' : '
            $indent = ' ' * $prefix.Length
            Write-Host $prefix -ForegroundColor $LabelColor -NoNewline
            $lineLen = $prefix.Length
            for ($i = 0; $i -lt $Items.Count; $i++) {
                $text = $Items[$i]
                if ($i -lt $Items.Count - 1) { $text += ',' }
                # Wrap before this item if it would not fit (always keep at least one item per line).
                if ($lineLen -gt $prefix.Length -and ($lineLen + 1 + $text.Length) -ge $width) {
                    Write-Host ''
                    Write-Host $indent -NoNewline
                    $lineLen = $indent.Length
                }
                elseif ($lineLen -gt $prefix.Length) {
                    Write-Host ' ' -NoNewline
                    $lineLen++
                }
                Write-Host $text -ForegroundColor $ItemColor -NoNewline
                $lineLen += $text.Length
            }
            Write-Host ''
        }

        foreach ($group in $groups) {
            $names = @($group.Group | ForEach-Object { $_.Name } | Sort-Object)
            & $writeWrapped $group.Name $names 'Cyan' 'White'
        }
        $aliases = @($script:WyattToolsIndex | ForEach-Object { $_.Aliases } | Sort-Object)
        if ($aliases.Count -gt 0) {
            & $writeWrapped 'Aliases' $aliases 'Yellow' 'Gray'
        }
        return
    }

    foreach ($group in $groups) {
        Write-Host "`n[$($group.Name)]" -ForegroundColor Cyan
        foreach ($entry in ($group.Group | Sort-Object { $_.Name })) {
            $help = Get-Help -Name $entry.Name -ErrorAction SilentlyContinue
            $label = $entry.Name
            if ($entry.Aliases.Count -gt 0) { $label += "  (" + ($entry.Aliases -join ', ') + ")" }
            Write-Host $label -ForegroundColor Green
            if ($help -and $help.Synopsis) {
                Write-Host ("  " + $help.Synopsis.Trim()) -ForegroundColor White
            }
            if ($help -and $help.Examples -and $help.Examples.Example) {
                $ex = @($help.Examples.Example)[0]
                Write-Host ("  e.g. " + $ex.Code) -ForegroundColor Yellow
            }
        }
    }
}

Set-Alias -Name tools -Value Show-WyattTools
