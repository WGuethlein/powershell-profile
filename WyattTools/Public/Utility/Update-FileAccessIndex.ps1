<#
.SYNOPSIS
    Scans file shares for folders with explicit permissions or blocked inheritance and saves an index.
.DESCRIPTION
    Walks the folder tree under each root over SMB (folders only; files are never read) and records
    only "break points": folders where permissions are set explicitly or inheritance is blocked.
    Everything else inherits from a parent, so the index stays small even on hundreds of terabytes.
    The root folder itself is recorded in full. Top-level child folders are scanned in parallel on
    a runspace pool. SIDs are translated to names once each; orphaned SIDs keep the SID text.
    The result (acl-index.csv, scan-errors.csv, scan-info.json) is what Get-FileAccess reads.
    Each file is written to a .tmp name first and then moved into place, so a reader never sees a
    half-written file. The scan itself is read-only; -WhatIf scans but does not write the index.
.PARAMETER Root
    One or more root folders (UNC or DFS paths). Default: FileAccessRoots in the WyattTools config.
.PARAMETER IndexPath
    Folder to write the index to. Default: FileAccessIndexPath in the config; if blank,
    %LOCALAPPDATA%\WyattTools\FileAccessIndex.
.PARAMETER Threads
    Worker threads (1-64) sharing one pool of folders, so a few huge folders still use every thread. Default 16.
.PARAMETER MaxDepth
    Deepest folder level to scan; 0 (default) means unlimited. The root itself is depth 0.
.PARAMETER ExcludeDirectory
    Folder names (not paths) to skip, case-insensitive.
    Default: $RECYCLE.BIN, System Volume Information, ~snapshot, .snapshot.
.EXAMPLE
    Update-FileAccessIndex
    Scans the roots from the config and writes the index to the configured location.
.EXAMPLE
    Update-FileAccessIndex -Root '\\contoso.com\files$\files' -Threads 32 -Verbose
    Scans one DFS root with 32 parallel workers and verbose output.
.EXAMPLE
    Update-FileAccessIndex -Root '\\contoso.com\files$\Projects' -MaxDepth 4 -IndexPath D:\Index
    Scans only four levels deep and writes the index to D:\Index.
.EXAMPLE
    pwsh.exe -NoProfile -Command "Import-Module C:\Tools\WyattTools\WyattTools.psd1; Update-FileAccessIndex"
    The command line for a weekly scheduled task (run it as a service account that can read every folder).
.NOTES
    Name: Update-FileAccessIndex
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-19
    Prerequisites: Windows PowerShell 5.1 or PowerShell 7; read access over SMB to the roots.
    The scanning account needs List folder / Read permissions on every folder. Folders it cannot
    read show up in scan-errors.csv, and access under them is missing from the index.
    Run under PowerShell 7 (pwsh) for paths longer than 260 characters; Windows PowerShell 5.1
    logs those folders as errors.
    Schedule it weekly (Task Scheduler, action "pwsh.exe", see the last example). Get-FileAccess
    warns when the index is older than 14 days.
    Share-level permissions are not read: Get-SmbShareAccess cannot query a Panzura filer. Effective
    access is the more restrictive of the share permissions and the NTFS permissions found here.
#>
function Update-FileAccessIndex {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Position = 0)]
        [string[]]$Root,

        [Parameter()]
        [string]$IndexPath,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$Threads = 16,

        [Parameter()]
        [ValidateRange(0, 1000)]
        [int]$MaxDepth = 0,

        [Parameter()]
        [string[]]$ExcludeDirectory = @('$RECYCLE.BIN', 'System Volume Information', '~snapshot', '.snapshot')
    )

    # Roots: parameter, else config (key may be missing in older config files).
    if (-not $Root) {
        $config = Get-WyattConfig
        if ($config -and $config.ContainsKey('FileAccessRoots')) { $Root = @($config.FileAccessRoots) }
    }
    $Root = @($Root | Where-Object { $_ })
    if ($Root.Count -eq 0) {
        throw 'No roots given. Pass -Root or set FileAccessRoots in the WyattTools config.psd1.'
    }
    $IndexPath = Get-FileAccessIndexPath -IndexPath $IndexPath

    # Keep reachable roots only; trim the trailing backslash (but keep "C:\").
    $reachable = New-Object System.Collections.Generic.List[string]
    foreach ($r in $Root) {
        $clean = $r.Trim().TrimEnd('\')
        if ($clean.EndsWith(':')) { $clean += '\' }
        if (Test-Path -LiteralPath $clean -PathType Container) { $reachable.Add($clean) }
        else { Write-Warning "Root not reachable, skipping: $r" }
    }
    if ($reachable.Count -eq 0) { throw 'None of the roots are reachable.' }

    $scanStarted = Get-Date
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $sidType   = [System.Security.Principal.SecurityIdentifier]
    $ntType    = [System.Security.Principal.NTAccount]
    $rawRows   = New-Object System.Collections.Generic.List[object]
    $errorRows = New-Object System.Collections.Generic.List[object]
    $excludeSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ExcludeDirectory) { $null = $excludeSet.Add($name) }

    # Shared work-stealing state (runspaces run in this process, so they share these objects).
    # Counters: [0] = workers currently busy, [1] = folders scanned by workers.
    $stack    = New-Object 'System.Collections.Concurrent.ConcurrentStack[object]'
    $rowQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    $errQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    $counters = [int[]]@(0, 0)
    $folders  = 0

    # Self-contained worker: runspaces do not see module functions. Each worker loops: pop one folder
    # from the shared stack, read its ACL, push its subfolders back. Children are pushed before the
    # busy counter drops, so "stack empty and nobody busy" reliably means the scan is finished.
    $worker = {
        param($Stack, $RowQueue, $ErrQueue, [int[]]$Counters, [int]$MaxDepth, [string[]]$Exclude)

        $excludeSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($name in $Exclude) { $null = $excludeSet.Add($name) }

        # Message text for an exception; flags the 260-character limit of Windows PowerShell 5.1.
        $describe = {
            param($Err)
            $ex = $Err.Exception
            while ($ex) {
                if ($ex -is [System.IO.PathTooLongException]) {
                    return 'Path too long (over 260 characters). Run under PowerShell 7 (pwsh) for long paths.'
                }
                if ($null -eq $ex.InnerException) { break }
                $ex = $ex.InnerException
            }
            return $ex.Message
        }

        # Counter update under a lock ([ref] on an array element does not alias, so Interlocked cannot be used).
        $bump = {
            param([int[]]$Array, [int]$Index, [int]$Delta)
            [System.Threading.Monitor]::Enter($Array)
            try { $Array[$Index] += $Delta; return $Array[$Index] }
            finally { [System.Threading.Monitor]::Exit($Array) }
        }

        while ($true) {
            $null = & $bump $Counters 0 1
            $item = $null
            if (-not $Stack.TryPop([ref]$item)) {
                $busy = & $bump $Counters 0 -1
                if ($Stack.IsEmpty -and $busy -eq 0) { break }
                Start-Sleep -Milliseconds 25
                continue
            }

            $path  = [string]$item.Path
            $depth = [int]$item.Depth
            $root  = [string]$item.Root
            try {
                # Permissions: only explicit ACEs, plus whether inheritance is blocked.
                try {
                    $sec      = [System.Security.AccessControl.DirectorySecurity]::new($path, 'Access')
                    $explicit = @($sec.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
                    $blocked  = [bool]$sec.AreAccessRulesProtected
                    if ($explicit.Count -gt 0 -or $blocked) {
                        foreach ($rule in $explicit) {
                            $rights = [int64]$rule.FileSystemRights
                            if ($rights -lt 0) { $rights += 4294967296 }
                            $RowQueue.Enqueue([pscustomobject]@{
                                    Root = $root; Path = $path; Depth = $depth; IsRoot = $false; Blocked = $blocked
                                    Sid = $rule.IdentityReference.Value; Type = $rule.AccessControlType.ToString()
                                    Rights = $rights; InheritanceFlags = $rule.InheritanceFlags.ToString()
                                    PropagationFlags = $rule.PropagationFlags.ToString(); IsInherited = [bool]$rule.IsInherited
                                })
                        }
                        if ($explicit.Count -eq 0) {
                            $RowQueue.Enqueue([pscustomobject]@{
                                    Root = $root; Path = $path; Depth = $depth; IsRoot = $false; Blocked = $blocked
                                    Sid = ''; Type = 'None'; Rights = [int64]0; InheritanceFlags = ''
                                    PropagationFlags = ''; IsInherited = $false
                                })
                        }
                    }
                }
                catch {
                    $ErrQueue.Enqueue([pscustomobject]@{ Path = $path; Operation = 'ReadAcl'; Message = (& $describe $_) })
                }

                # Subfolders (skip reparse points and excluded names; respect MaxDepth).
                if ($MaxDepth -eq 0 -or $depth -lt $MaxDepth) {
                    try {
                        foreach ($dir in ([System.IO.DirectoryInfo]$path).EnumerateDirectories()) {
                            if ($excludeSet.Contains($dir.Name)) { continue }
                            if (($dir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                            $Stack.Push([pscustomobject]@{ Root = $root; Path = ($path.TrimEnd('\') + '\' + $dir.Name); Depth = ($depth + 1) })
                        }
                    }
                    catch {
                        $ErrQueue.Enqueue([pscustomobject]@{ Path = $path; Operation = 'ListFolders'; Message = (& $describe $_) })
                    }
                }
            }
            catch {
                $ErrQueue.Enqueue([pscustomobject]@{ Path = $path; Operation = 'ReadAcl'; Message = $_.Exception.Message })
            }
            finally {
                $null = & $bump $Counters 1 1
                $null = & $bump $Counters 0 -1
            }
        }
    }

    $pool = $null
    $pending = New-Object System.Collections.Generic.List[object]
    try {
        # Roots: full ACL in this thread, then every direct child folder goes on the shared stack.
        foreach ($r in $reachable) {
            try {
                $sec = [System.Security.AccessControl.DirectorySecurity]::new($r, 'Access')
                $blocked = [bool]$sec.AreAccessRulesProtected
                foreach ($rule in @($sec.GetAccessRules($true, $true, $sidType))) {
                    $rights = [int64]$rule.FileSystemRights
                    if ($rights -lt 0) { $rights += 4294967296 }
                    $rawRows.Add([pscustomobject]@{
                            Root = $r; Path = $r; Depth = 0; IsRoot = $true; Blocked = $blocked
                            Sid = $rule.IdentityReference.Value; Type = $rule.AccessControlType.ToString()
                            Rights = $rights; InheritanceFlags = $rule.InheritanceFlags.ToString()
                            PropagationFlags = $rule.PropagationFlags.ToString(); IsInherited = [bool]$rule.IsInherited
                        })
                }
            }
            catch {
                $errorRows.Add([pscustomobject]@{ Path = $r; Operation = 'ReadAcl'; Message = $_.Exception.Message })
            }
            $folders++

            # Children are depth 1: always within MaxDepth (0 = unlimited, otherwise at least 1).
            try {
                foreach ($dir in ([System.IO.DirectoryInfo]$r).EnumerateDirectories()) {
                    if ($excludeSet.Contains($dir.Name)) { continue }
                    if (($dir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    $stack.Push([pscustomobject]@{ Root = $r; Path = ($r.TrimEnd('\') + '\' + $dir.Name); Depth = 1 })
                }
            }
            catch {
                $errorRows.Add([pscustomobject]@{ Path = $r; Operation = 'ListFolders'; Message = $_.Exception.Message })
            }
        }

        Write-Verbose "Scanning with $Threads threads; $($stack.Count) top-level folders queued."
        $pool = [runspacefactory]::CreateRunspacePool(1, $Threads)
        $pool.Open()
        for ($i = 0; $i -lt $Threads; $i++) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            $null = $ps.AddScript($worker.ToString()).AddArgument($stack).AddArgument($rowQueue).AddArgument($errQueue).AddArgument($counters).AddArgument($MaxDepth).AddArgument([string[]]@($ExcludeDirectory))
            $pending.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
        }

        # Poll until every worker has exited; total is unknown, so progress has no percentage.
        while ($pending.Count -gt 0) {
            foreach ($p in @($pending | Where-Object { $_.Handle.IsCompleted })) {
                try { $null = $p.PS.EndInvoke($p.Handle) }
                catch { $errorRows.Add([pscustomobject]@{ Path = ''; Operation = 'ListFolders'; Message = "Worker failed: $($_.Exception.Message)" }) }
                $p.PS.Dispose()
                $null = $pending.Remove($p)
            }
            Write-Progress -Activity 'Scanning folder permissions' -Status "$($counters[1]) folders scanned; $($stack.Count) folders queued"
            if ($pending.Count -gt 0) { Start-Sleep -Milliseconds 500 }
        }
        Write-Progress -Activity 'Scanning folder permissions' -Completed
    }
    finally {
        foreach ($p in $pending) { $p.PS.Dispose() }
        if ($pool) { $pool.Close(); $pool.Dispose() }
    }

    # Merge worker results.
    $folders += $counters[1]
    foreach ($row in $rowQueue) { $rawRows.Add($row) }
    foreach ($e in $errQueue) { $errorRows.Add($e) }

    # Translate SIDs to names here, once per SID; orphaned SIDs keep the SID text.
    $names = @{}
    $indexRows = foreach ($row in $rawRows) {
        $identity = ''
        if ($row.Sid) {
            if (-not $names.ContainsKey($row.Sid)) {
                try { $names[$row.Sid] = ([System.Security.Principal.SecurityIdentifier]$row.Sid).Translate($ntType).Value }
                catch { $names[$row.Sid] = $row.Sid }
            }
            $identity = $names[$row.Sid]
        }
        [pscustomobject][ordered]@{
            Root               = $row.Root
            Path               = $row.Path
            Depth              = $row.Depth
            IsRoot             = $row.IsRoot
            InheritanceBlocked = $row.Blocked
            Identity           = $identity
            Sid                = $row.Sid
            Type               = $row.Type
            Rights             = $row.Rights
            InheritanceFlags   = $row.InheritanceFlags
            PropagationFlags   = $row.PropagationFlags
            IsInherited        = $row.IsInherited
        }
    }
    $indexRows = @($indexRows)
    $sw.Stop()
    $breakPoints = @($indexRows | ForEach-Object { $_.Path } | Sort-Object -Unique).Count
    $scanFinished = Get-Date

    $summary = [PSCustomObject]@{
        IndexPath     = $IndexPath
        Roots         = @($reachable)
        FoldersScanned = $folders
        BreakPoints   = $breakPoints
        Errors        = $errorRows.Count
        Duration      = $sw.Elapsed
    }

    if (-not $PSCmdlet.ShouldProcess($IndexPath, 'Write file access index')) { return }

    if (-not (Test-Path -LiteralPath $IndexPath)) { $null = New-Item -Path $IndexPath -ItemType Directory -Force }
    $info = [pscustomobject][ordered]@{
        ScanStarted    = $scanStarted.ToString('yyyy-MM-ddTHH:mm:ss')
        ScanFinished   = $scanFinished.ToString('yyyy-MM-ddTHH:mm:ss')
        Duration       = $sw.Elapsed.ToString()
        Roots          = @($reachable)
        FoldersScanned = $folders
        BreakPoints    = $breakPoints
        Errors         = $errorRows.Count
        ComputerName   = $env:COMPUTERNAME
        UserName       = $env:USERNAME
        PSVersion      = $PSVersionTable.PSVersion.ToString()
    }

    # Write to .tmp, then move over the real name so readers never see a half-written file.
    $targets = @(
        @{ Name = 'acl-index.csv';   Write = { param($f) $indexRows | Export-Csv -LiteralPath $f -NoTypeInformation -Encoding UTF8 } }
        @{ Name = 'scan-errors.csv'; Write = { param($f) $errorRows | Select-Object Path, Operation, Message | Export-Csv -LiteralPath $f -NoTypeInformation -Encoding UTF8 } }
        @{ Name = 'scan-info.json';  Write = { param($f) $info | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $f -Encoding UTF8 } }
    )
    foreach ($t in $targets) {
        $final = Join-Path $IndexPath $t.Name
        $tmp   = "$final.tmp"
        & $t.Write $tmp
        Move-Item -LiteralPath $tmp -Destination $final -Force
    }

    if ($errorRows.Count -gt 0) {
        Write-Warning "$($errorRows.Count) folders could not be read. See $(Join-Path $IndexPath 'scan-errors.csv')."
    }
    $summary
}
