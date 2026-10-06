<#
.SYNOPSIS
    Copies a folder with robocopy: multithreaded, resumable, and never overwrites by default.
.DESCRIPTION
    Wraps robocopy for the common "Explorer says this will take a day" case: lots of small files,
    often to a network share. Copies subfolders (including empty ones) with 32 threads, retries a
    failed file twice 5 seconds apart, and skips any file that already exists at the destination
    unless -Overwrite is given. Leave out -Source or -Destination to pick the folder in a dialog.
    Interrupted copies are safe to re-run; files already copied are skipped. -WhatIf runs robocopy
    with /L, which lists what would be copied without touching anything. Robocopy's own summary is
    shown on screen and written to a log, and a result object with the exit code is returned.
.PARAMETER Source
    Folder to copy from. Leave out to choose it in a folder dialog.
.PARAMETER Destination
    Folder to copy into (created if missing). Leave out to choose it in a folder dialog.
    A UNC path (\\server\share\...) avoids the problem of mapped drives being missing in an
    elevated shell.
.PARAMETER Threads
    Parallel copy threads (robocopy /MT). Default 32; use 8-16 for a few large files.
.PARAMETER Retries
    Times to retry a failed file (/R). Default 2. Robocopy's own default is one million.
.PARAMETER WaitSeconds
    Seconds between retries (/W). Default 5.
.PARAMETER Overwrite
    Copy files that already exist at the destination when they differ (changed, newer or older).
    Without it, existing destination files are never touched (/XC /XN /XO).
.PARAMETER ExcludeFile
    File names or wildcards to skip (/XF), for example '*.tmp', 'Thumbs.db'.
.PARAMETER ExcludeDirectory
    Folder names or paths to skip (/XD), for example '.git', 'node_modules'.
.PARAMETER Unbuffered
    Use unbuffered I/O (/J). Faster for very large files, slower for small ones.
.PARAMETER Restartable
    Restartable mode (/Z). Resumes a large file mid-way after a dropped link, but is slower.
.PARAMETER ListFiles
    Log every file and folder name. Off by default because printing tens of thousands of names
    slows the copy; the summary counts are always shown.
.PARAMETER LogPath
    Log file to write. Default: %TEMP%\fcopy-<timestamp>.log. Overwritten if it exists.
.EXAMPLE
    fcopy C:\TempProject 'X:\Projects\Archive\Project Drive'
    Copies everything not already at the destination, leaving existing files alone.
.EXAMPLE
    fcopy
    Opens a folder dialog for the source, then one for the destination, then copies.
.EXAMPLE
    fcopy C:\TempProject '\\fs01\Projects\Archive\Project Drive' -WhatIf -ListFiles
    Dry run: lists every file that would be copied, without copying anything.
.EXAMPLE
    Copy-FolderFast D:\Jobs \\fs01\Jobs -Overwrite -ExcludeDirectory '.git','node_modules' -ExcludeFile '*.tmp' -Threads 64
    Updates changed files too, skipping git folders, node_modules and temp files.
.EXAMPLE
    $r = fcopy D:\Video \\nas01\Video -Threads 8 -Unbuffered -Restartable
    if (-not $r.Success) { tail $r.LogPath -Lines 50 }
    A few huge files over a flaky link; shows the end of the log if anything failed.
.NOTES
    Name: Copy-FolderFast
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-06
    Prerequisites: robocopy.exe (built into Windows). Folder dialogs need an interactive desktop session.
    Exit codes 0-7 mean success (bit 1 = files copied, 2 = extra files at destination,
    4 = mismatches); 8 or higher means some files or the whole job failed.
#>
function Copy-FolderFast {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Position = 0)]
        [string]$Source,

        [Parameter(Position = 1)]
        [string]$Destination,

        [Parameter()]
        [ValidateRange(1, 128)]
        [int]$Threads = 32,

        [Parameter()]
        [ValidateRange(0, 1000)]
        [int]$Retries = 2,

        [Parameter()]
        [ValidateRange(0, 3600)]
        [int]$WaitSeconds = 5,

        [Parameter()]
        [switch]$Overwrite,

        [Parameter()]
        [string[]]$ExcludeFile,

        [Parameter()]
        [string[]]$ExcludeDirectory,

        [Parameter()]
        [switch]$Unbuffered,

        [Parameter()]
        [switch]$Restartable,

        [Parameter()]
        [switch]$ListFiles,

        [Parameter()]
        [string]$LogPath
    )

    # Shows a folder-browse dialog; returns the chosen path or $null if cancelled.
    function Select-Folder([string]$Title, [bool]$AllowNew) {
        if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
            return Read-Host "$Title (folder dialogs need an STA shell; type the path)"
        }
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = $Title
        $dialog.ShowNewFolderButton = $AllowNew
        try {
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.SelectedPath }
            return $null
        }
        finally { $dialog.Dispose() }
    }

    # Robocopy reads a trailing backslash before the closing quote as an escaped quote, so trim
    # it; a bare drive root ("C:") would mean the current folder on that drive, so use "C:\.".
    function Format-RoboPath([string]$Path) {
        $trimmed = $Path.TrimEnd('\')
        if ($trimmed.EndsWith(':')) { return "$trimmed\." }
        return $trimmed
    }

    if (-not $Source) { $Source = Select-Folder 'Choose the folder to copy FROM' $false }
    if (-not $Source) { throw 'No source folder chosen.' }
    if (-not $Destination) { $Destination = Select-Folder "Choose the folder to copy '$(Split-Path $Source -Leaf)' INTO" $true }
    if (-not $Destination) { throw 'No destination folder chosen.' }

    if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
        throw "Source folder not found: $Source"
    }
    # Mapped drives made in a normal session are invisible to an elevated one; say so plainly.
    if ($Destination.Length -ge 2 -and $Destination[1] -eq ':' -and -not (Test-Path -LiteralPath "$($Destination.Substring(0, 2))\")) {
        throw "Drive $($Destination.Substring(0, 2)) is not available in this session. If it is a mapped drive and this shell is elevated, use a non-elevated shell or the UNC path (\\server\share\...)."
    }
    $srcFull  = (Resolve-Path -LiteralPath $Source).ProviderPath.TrimEnd('\')
    $destFull = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Destination).TrimEnd('\')

    if ($srcFull -eq $destFull) { throw 'Source and destination are the same folder.' }
    if ($destFull.StartsWith("$srcFull\", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Destination is inside the source folder; robocopy would copy the copy into itself.'
    }

    if (-not $LogPath) { $LogPath = Join-Path $env:TEMP ("fcopy-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date)) }
    $LogPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($LogPath)

    # Build the robocopy argument list (PowerShell quotes any argument containing spaces).
    $roboArgs = New-Object System.Collections.Generic.List[string]
    $roboArgs.AddRange([string[]]@(
        (Format-RoboPath $srcFull), (Format-RoboPath $destFull),
        '/E', "/MT:$Threads", "/R:$Retries", "/W:$WaitSeconds", '/NP', "/LOG:$LogPath", '/TEE'
    ))
    if (-not $Overwrite)   { $roboArgs.AddRange([string[]]@('/XC', '/XN', '/XO')) }
    if (-not $ListFiles)   { $roboArgs.AddRange([string[]]@('/NFL', '/NDL')) }
    if ($Unbuffered)       { $roboArgs.Add('/J') }
    if ($Restartable)      { $roboArgs.Add('/Z') }
    if ($ExcludeFile)      { $roboArgs.Add('/XF'); $roboArgs.AddRange([string[]]$ExcludeFile) }
    if ($ExcludeDirectory) { $roboArgs.Add('/XD'); $roboArgs.AddRange([string[]]$ExcludeDirectory) }

    # -WhatIf becomes a robocopy dry run (/L) rather than doing nothing, so the counts are visible.
    $dryRun = [bool]$WhatIfPreference
    if ($dryRun) {
        $roboArgs.Add('/L')
        Write-Host "Dry run (/L): nothing will be copied." -ForegroundColor Cyan
    }
    elseif (-not $PSCmdlet.ShouldProcess("$srcFull -> $destFull", 'Copy with robocopy')) {
        return
    }

    Write-Verbose "robocopy $($roboArgs -join ' ')"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & robocopy.exe $roboArgs.ToArray() | Out-Host
        $exitCode = $LASTEXITCODE
    }
    catch {
        throw "robocopy failed to start: $($_.Exception.Message)"
    }
    $sw.Stop()

    # Translate the exit code bit flags into words.
    $parts = New-Object System.Collections.Generic.List[string]
    if ($exitCode -band 16) { $parts.Add('fatal error, nothing copied (check paths and permissions)') }
    if ($exitCode -band 8)  { $parts.Add('some files failed after retries') }
    if ($exitCode -band 4)  { $parts.Add('mismatched files or folders found') }
    if ($exitCode -band 2)  { $parts.Add('extra files at destination (left alone)') }
    if ($exitCode -band 1)  { $parts.Add($(if ($dryRun) { 'files would be copied' } else { 'files copied' })) }
    if ($exitCode -eq 0)    { $parts.Add('nothing to copy; destination already has everything') }

    $success = $exitCode -lt 8
    if (-not $success) { Write-Warning "robocopy exit code $exitCode. See the log: $LogPath" }

    [PSCustomObject]@{
        Source      = $srcFull
        Destination = $destFull
        DryRun      = $dryRun
        Success     = $success
        ExitCode    = $exitCode
        Result      = ($parts -join '; ')
        Duration    = $sw.Elapsed
        LogPath     = $LogPath
    }
}

Set-Alias -Name fcopy -Value Copy-FolderFast
