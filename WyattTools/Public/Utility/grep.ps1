<#
.SYNOPSIS
    grep for PowerShell: searches files or piped output for a regex pattern.
.DESCRIPTION
    A grep-style wrapper around Select-String. Like real grep it is case-sensitive unless -i is
    given, prints matching lines as plain text, and prefixes the file name when more than one
    file is searched. Piped objects (e.g. Get-Process) are searched as the text you would see on
    screen. Patterns are .NET regular expressions. Flags must be given separately (-r -n, not -rn).
    For large folder trees, ripgrep (rg) is much faster; Bootstrap installs it.
.PARAMETER Pattern
    Regular expression to search for.
.PARAMETER Path
    Files or folders to search. Folders need -r. Defaults to the current folder with -r.
.PARAMETER InputObject
    Piped input to search.
.PARAMETER i
    Ignore case.
.PARAMETER r
    Search folders recursively.
.PARAMETER v
    Show lines that do NOT match.
.PARAMETER n
    Prefix each line with its line number.
.PARAMETER l
    Print only the names of files that contain a match.
.PARAMETER c
    Print only the count of matching lines (per file when searching files).
.EXAMPLE
    grep error app.log
.EXAMPLE
    grep -i -n 'timeout' *.log
.EXAMPLE
    grep -r -l 'Connect-MgGraph' .
.EXAMPLE
    ipconfig | grep IPv4
.NOTES
    Name: grep
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: None
#>
function grep {
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Pattern,

        [Parameter(Position = 1, ValueFromRemainingArguments)]
        [string[]]$Path,

        [Parameter(ValueFromPipeline)]
        [object]$InputObject,

        [switch]$i,
        [switch]$r,
        [switch]$v,
        [switch]$n,
        [switch]$l,
        [switch]$c
    )

    begin {
        $piped = New-Object System.Collections.Generic.List[object]
        $sls = @{ Pattern = $Pattern; CaseSensitive = (-not $i); NotMatch = $v.IsPresent }
    }

    process {
        if ($null -ne $InputObject) { $piped.Add($InputObject) }
    }

    end {
        # --- Piped input: search the text as it would appear on screen. ---
        if ($piped.Count -gt 0 -and -not $Path) {
            $lines = $piped | Out-String -Stream -Width 4096
            $found = @($lines | Select-String @sls)
            if ($c) { return $found.Count }
            foreach ($m in $found) {
                if ($n) { "$($m.LineNumber):$($m.Line)" } else { $m.Line }
            }
            return
        }

        # --- Files: expand paths (folders only with -r). ---
        if (-not $Path) {
            if ($r) { $Path = @('.') }
            else { Write-Error 'grep: no file given (use -r to search the current folder, or pipe input).'; return }
        }
        $files = New-Object System.Collections.Generic.List[string]
        foreach ($p in $Path) {
            foreach ($item in @(Get-Item -Path $p -ErrorAction SilentlyContinue)) {
                if ($item.PSIsContainer) {
                    if ($r) { Get-ChildItem -LiteralPath $item.FullName -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $files.Add($_.FullName) } }
                    else { Write-Warning "grep: $p is a directory (use -r)" }
                }
                else { $files.Add($item.FullName) }
            }
            if (-not (Test-Path -Path $p)) { Write-Warning "grep: $p not found" }
        }
        if ($files.Count -eq 0) { return }

        # grep shows file names when more than one file could match.
        $showName = $r -or $files.Count -gt 1
        $relative = @{}
        $display = {
            param($full)
            if (-not $relative.ContainsKey($full)) {
                $rel = Resolve-Path -LiteralPath $full -Relative
                $relative[$full] = $rel -replace '^\.\\', ''
            }
            $relative[$full]
        }

        $found = @(Select-String -LiteralPath $files @sls -ErrorAction SilentlyContinue)

        if ($l) {
            $found | Select-Object -ExpandProperty Path -Unique | ForEach-Object { & $display $_ }
            return
        }
        if ($c) {
            if (-not $showName) { return $found.Count }
            # Every file gets a count line, including zero, like grep -c.
            foreach ($f in $files) {
                $count = @($found | Where-Object { $_.Path -eq $f }).Count
                "$(& $display $f):$count"
            }
            return
        }
        foreach ($m in $found) {
            $prefix = ''
            if ($showName) { $prefix = "$(& $display $m.Path):" }
            if ($n) { $prefix += "$($m.LineNumber):" }
            "$prefix$($m.Line)"
        }
    }
}
