<#
.SYNOPSIS
    Scans a local drive for files that contain PII or secrets and writes a masked CSV report.
.DESCRIPTION
    Walks the user-data areas of a local drive (default: C:\Users plus the other top-level folders
    on C:) and looks for PII (SSNs, card numbers, bank routing and account numbers, dates of birth,
    driver's license and passport numbers) and secrets (private keys, cloud and API tokens,
    passwords in config files, PowerShell credential files, saved RDP passwords, key and password
    store files). Content is scanned on a runspace pool. Office OpenXML files (docx, xlsx, pptx)
    are read part by part. Key stores such as .pfx or .kdbx are flagged by name only.
    The scan is strictly read-only: files are opened for reading with sharing allowed and are never
    changed, moved, or deleted, and OneDrive cloud-only placeholders are skipped unless
    -IncludeCloudFiles is given. Matched values are masked inside the worker and never stored in
    full. The CSV has one row per file per finding type. The report still shows where sensitive
    data lives, so treat it as sensitive and delete it after triage. Unreadable folders and files
    are counted and listed in a separate -errors.csv; they never stop the scan.
.PARAMETER Path
    Folders to scan. Default: C:\Users plus every top-level folder on C: except Windows,
    Program Files, Program Files (x86), ProgramData, $Recycle.Bin, System Volume Information,
    Recovery, PerfLogs, $WinREAgent, and OneDriveTemp. Nested roots are merged.
.PARAMETER ExcludeDirectory
    Extra folder names, wildcards, or path fragments to skip, added to the built-in skips
    (AppData\Local\Microsoft, AppData\Local\Packages, AppData\Local\Temp\*\Cache*, browser cache
    folders, node_modules, .git\objects, __pycache__, .nuget\packages, WinSxS).
.PARAMETER Category
    PII, Secret, or both (default).
.PARAMETER MaxFileSizeMB
    Content is not read from files above this size; they are counted as skipped. Default 50.
.PARAMETER IncludeCloudFiles
    Also read cloud-only placeholders (OneDrive Files On-Demand). This downloads them. Off by default.
.PARAMETER ThrottleLimit
    Number of runspaces reading files. Default: the number of logical processors.
.PARAMETER OutputPath
    CSV file to write. Default: SensitiveData-<COMPUTERNAME>-<yyyyMMdd-HHmmss>.csv in the folder
    from Get-ExportDirectory. The folder is created if missing.
.PARAMETER PassThru
    Also return the finding objects.
.EXAMPLE
    piiscan
    Scans the default folders for PII and secrets and writes the CSV to the export directory.
.EXAMPLE
    Find-SensitiveData -Path $env:USERPROFILE -Category Secret -OutputPath D:\triage\secrets.csv
    Looks only for secrets in your own profile and writes the report to a chosen file.
.EXAMPLE
    $f = piiscan -Path D:\Share -PassThru -ThrottleLimit 4 -ExcludeDirectory 'Archive','*.old'
    $f | Where-Object Confidence -eq High | Sort-Object Path | Format-Table Path, FindingType, Sample
    Scans a data drive with four workers, skipping some folders, and shows the high-confidence hits.
.NOTES
    Name: Find-SensitiveData
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-21
    Prerequisites: Windows PowerShell 5.1 or PowerShell 7. Run elevated to read other users'
    profiles; otherwise it scans what the current user can read.
    Junctions and symlinks are not followed (OneDrive sync folders are scanned). Low-confidence rows are expected to be
    noisy; this is a triage aid, not a DLP product. Not covered: PDF, images, legacy .doc/.xls,
    PST/OST, archives, browser password stores, Credential Manager, the registry.
    A ConfigPassword value that contains spaces is reported from its first word only.
#>
function Find-SensitiveData {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Position = 0)]
        [string[]]$Path,

        [Parameter()]
        [string[]]$ExcludeDirectory,

        [Parameter()]
        [ValidateSet('PII', 'Secret')]
        [string[]]$Category = @('PII', 'Secret'),

        [Parameter()]
        [ValidateRange(1, 10240)]
        [int]$MaxFileSizeMB = 50,

        [Parameter()]
        [switch]$IncludeCloudFiles,

        [Parameter()]
        [ValidateRange(1, 256)]
        [int]$ThrottleLimit = [Environment]::ProcessorCount,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [switch]$PassThru
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    # Junctions and symlinks are never followed (they cause profile loops). Other reparse points,
    # such as the OneDrive sync folder, are ordinary folders and are scanned.
    if (-not ('SensitiveDataReparse' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SensitiveDataReparse {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_DATA {
        public uint dwFileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint dwReserved0;
        public uint dwReserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstFileW(string fileName, out WIN32_FIND_DATA data);
    [DllImport("kernel32.dll")]
    private static extern bool FindClose(IntPtr handle);
    // True for junctions and symlinks, and when the tag cannot be read (treated as a link, so skipped).
    public static bool IsLinkOrUnknown(string path) {
        WIN32_FIND_DATA data;
        IntPtr h = FindFirstFileW(path, out data);
        if (h == new IntPtr(-1)) { return true; }
        FindClose(h);
        return data.dwReserved0 == 0xA0000003u || data.dwReserved0 == 0xA000000Cu;
    }
}
'@
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ci = [System.StringComparer]::OrdinalIgnoreCase

    # --- Roots -------------------------------------------------------------------------------
    $alwaysSkipTop = @('Windows', 'Program Files', 'Program Files (x86)', 'ProgramData', '$Recycle.Bin',
        'System Volume Information', 'Recovery', 'PerfLogs', '$WinREAgent', 'OneDriveTemp')
    $candidates = New-Object System.Collections.Generic.List[string]
    if (-not $Path) {
        $sysRoot = $env:SystemDrive + '\'
        $candidates.Add($sysRoot + 'Users')
        try {
            foreach ($d in (New-Object System.IO.DirectoryInfo($sysRoot)).EnumerateDirectories()) {
                if ($alwaysSkipTop -contains $d.Name) { continue }
                if (([int]$d.Attributes -band 0x400) -ne 0 -and [SensitiveDataReparse]::IsLinkOrUnknown($d.FullName)) { continue }
                $candidates.Add($d.FullName)
            }
        }
        catch { Write-Warning "Could not list ${sysRoot}: $($_.Exception.Message)" }
    }
    else {
        foreach ($p in $Path) { $candidates.Add($p) }
    }

    $valid = New-Object System.Collections.Generic.List[string]
    foreach ($c in $candidates) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $full = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($c.Trim()).TrimEnd('\')
        if ($full.EndsWith(':')) { $full += '\' }
        if (Test-Path -LiteralPath $full -PathType Container) {
            if (-not $valid.Contains($full)) { $valid.Add($full) }
        }
        else { Write-Warning "Path not found, skipping: $c" }
    }
    # Drop roots that sit inside another root so nothing is scanned twice.
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($r in $valid) {
        $nested = $false
        foreach ($o in $valid) {
            if ($o -ne $r -and $r.StartsWith($o.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)) { $nested = $true; break }
        }
        if (-not $nested) { $roots.Add($r) }
    }
    if ($roots.Count -eq 0) { throw 'None of the paths exist; nothing to scan.' }

    # --- Output path -------------------------------------------------------------------------
    if (-not $OutputPath) {
        $OutputPath = Join-Path (Get-ExportDirectory) ('SensitiveData-{0}-{1:yyyyMMdd-HHmmss}.csv' -f $env:COMPUTERNAME, (Get-Date))
    }
    $OutputPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutputPath)

    # --- Exclusions --------------------------------------------------------------------------
    $builtInNames = @('node_modules', '__pycache__', 'WinSxS', '$Recycle.Bin', 'System Volume Information',
        'Cache', 'Code Cache', 'GPUCache', 'ShaderCache', 'GrShaderCache', 'Cache2', 'CacheStorage', 'Cache_Data')
    $builtInPaths = @('AppData\Local\Microsoft', 'AppData\Local\Packages', 'AppData\Local\Temp\*\Cache*',
        '.git\objects', '.nuget\packages')
    $wcOpt = [System.Management.Automation.WildcardOptions]::IgnoreCase
    $nameWc = New-Object System.Collections.Generic.List[object]
    $pathWc = New-Object System.Collections.Generic.List[object]
    foreach ($n in $builtInNames) { $nameWc.Add((New-Object System.Management.Automation.WildcardPattern([System.Management.Automation.WildcardPattern]::Escape($n), $wcOpt))) }
    foreach ($n in (@($builtInPaths) + @($ExcludeDirectory | Where-Object { $_ }))) {
        $pat = $n.Trim().TrimEnd('\')
        if ($pat.Contains('\')) {
            if (-not [System.IO.Path]::IsPathRooted($pat)) { $pat = '*\' + $pat }
            $pathWc.Add((New-Object System.Management.Automation.WildcardPattern($pat, $wcOpt)))
        }
        elseif ($builtInNames -notcontains $pat) {
            $nameWc.Add((New-Object System.Management.Automation.WildcardPattern($pat, $wcOpt)))
        }
    }

    # --- File type tables --------------------------------------------------------------------
    $textExt = New-Object 'System.Collections.Generic.HashSet[string]' $ci
    foreach ($e in 'txt csv tsv log json xml yml yaml ini cfg conf config env properties toml ps1 psm1 psd1 py js ts cs sql sh bat cmd md html htm rdp'.Split(' ')) { $null = $textExt.Add('.' + $e) }
    $officeExt = New-Object 'System.Collections.Generic.HashSet[string]' $ci
    foreach ($e in 'docx xlsx pptx docm xlsm'.Split(' ')) { $null = $officeExt.Add('.' + $e) }
    $nameExt = New-Object 'System.Collections.Generic.HashSet[string]' $ci
    foreach ($e in 'pfx p12 pem key ppk jks keystore publishsettings'.Split(' ')) { $null = $nameExt.Add('.' + $e) }
    $nameFull = New-Object 'System.Collections.Generic.HashSet[string]' $ci
    foreach ($e in 'id_rsa id_dsa id_ecdsa id_ed25519 .git-credentials .netrc _netrc .pgpass'.Split(' ')) { $null = $nameFull.Add($e) }
    $wantSecret = $Category -contains 'Secret'

    # --- Detectors (regexes compiled once and shared with the workers) -----------------------
    $detectors = New-Object System.Collections.Generic.List[object]
    $timeout = [TimeSpan]::FromSeconds(2)
    foreach ($d in (Get-SensitiveDataDetector)) {
        if ($Category -notcontains $d.Category) { continue }
        $opts = [System.Text.RegularExpressions.RegexOptions]::Compiled
        if ($d.IgnoreCase) { $opts = $opts -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
        $ctx = $null
        if ($d.Context) {
            $ctx = New-Object System.Text.RegularExpressions.Regex($d.Context, ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled), $timeout)
        }
        $detectors.Add([PSCustomObject]@{
                FindingType = $d.FindingType; Category = $d.Category; Confidence = $d.Confidence
                Regex = (New-Object System.Text.RegularExpressions.Regex($d.Pattern, $opts, $timeout))
                Context = $ctx; Window = $d.Window; Validator = $d.Validator; MaskMode = $d.MaskMode
                NeedsDigit = $d.NeedsDigit; Hint = [string[]]@($d.Hint); Requires = $d.Requires
                SampleText = $d.SampleText
            })
    }
    $requiresList = [string[]]@($detectors | Where-Object { $_.Requires } | ForEach-Object { $_.Requires } | Select-Object -Unique)

    # Runspaces cannot see module functions, so the helpers travel as text.
    $prelude = (@('Test-SensitiveDataValidator', 'ConvertTo-MaskedValue') | ForEach-Object {
            "function $_ {`n" + (Get-Command -Name $_ -CommandType Function).ScriptBlock.ToString() + "`n}"
        }) -join "`n"

    # --- Worker: reads one file at a time from the shared queue ------------------------------
    # Counters: [0] = 1 once enumeration is finished, [1] = files read by workers.
    $worker = {
        param($Queue, $Results, $Errors, [int[]]$Counters, $Detectors, [string]$Prelude, [string[]]$RequiresList)

        Add-Type -AssemblyName System.IO.Compression
        . ([scriptblock]::Create($Prelude))

        $digitRx   = New-Object System.Text.RegularExpressions.Regex('\d')
        $boundary  = New-Object System.Text.RegularExpressions.Regex('</w:p>|</w:tc>|</w:tr>|<w:br/>|<w:tab/>|</row>|</c>|</si>|</a:p>')
        $tagRx     = New-Object System.Text.RegularExpressions.Regex('<[^>]*>')
        $partRx    = New-Object System.Text.RegularExpressions.Regex('^(?:word/(?:document|comments|header\d*|footer\d*)\.xml|xl/sharedStrings\.xml|xl/worksheets/[^/]+\.xml|ppt/slides/[^/]+\.xml)$', 'IgnoreCase')
        $acc       = @{}
        $seen      = @{}
        $state     = @{ Err = $null }

        # Innermost exception message, without the method-call wrapper text.
        function Get-InnerMessage($Err) {
            $ex = $Err.Exception
            while ($ex.InnerException) { $ex = $ex.InnerException }
            return $ex.Message
        }

        # Runs every detector on one line (or XML text); accumulates masked results in $acc.
        function Invoke-LineScan([string]$Line, [string]$Loc, $Detectors, [string[]]$RequiresList) {
            if ($Line.Length -lt 6) { return }
            $hasDigit = $digitRx.IsMatch($Line)
            foreach ($r in $RequiresList) {
                if (-not $seen[$r] -and $Line.IndexOf($r, [System.StringComparison]::Ordinal) -ge 0) { $seen[$r] = $true }
            }
            foreach ($d in $Detectors) {
                if ($d.NeedsDigit -and -not $hasDigit) { continue }
                if ($d.Requires -and -not $seen[$d.Requires]) { continue }
                if ($d.Hint.Count -gt 0) {
                    $hit = $false
                    foreach ($h in $d.Hint) {
                        if ($Line.IndexOf($h, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $true; break }
                    }
                    if (-not $hit) { continue }
                }
                try {
                    if ($d.Context -and -not $d.Context.IsMatch($Line)) { continue }
                    $m = $d.Regex.Match($Line)
                    while ($m.Success) {
                        $ok = $true
                        if ($d.Context) {
                            $s = [Math]::Max(0, $m.Index - $d.Window)
                            $e = [Math]::Min($Line.Length, $m.Index + $m.Length + $d.Window)
                            $ok = $d.Context.IsMatch($Line.Substring($s, $e - $s))
                        }
                        if ($ok) {
                            $val = $m.Value
                            $g = $m.Groups['val']
                            if ($g.Success) { $val = $g.Value }
                            if ($d.Validator) { $ok = Test-SensitiveDataValidator -Name $d.Validator -Value $val }
                        }
                        if ($ok) {
                            $entry = $acc[$d.FindingType]
                            if ($entry) { $entry.Count++ }
                            else {
                                if ($d.MaskMode -eq 'Literal') { $sample = $d.SampleText }
                                else { $sample = ConvertTo-MaskedValue -Value $val -Mode $d.MaskMode }
                                $acc[$d.FindingType] = [PSCustomObject]@{ Det = $d; Count = 1; First = $Loc; Sample = $sample }
                            }
                        }
                        $m = $m.NextMatch()
                    }
                }
                catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
                    $state.Err = 'A pattern timed out on a very long line; results for this file may be incomplete.'
                }
            }
        }

        $item = $null
        while ($true) {
            $done = $Counters[0]
            if (-not $Queue.TryDequeue([ref]$item)) {
                if ($done -eq 1) { break }
                Start-Sleep -Milliseconds 20
                continue
            }
            $acc.Clear(); $seen.Clear(); $state.Err = $null
            try {
                $fs = [System.IO.File]::Open($item.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
                    ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
                try {
                    if ($item.Kind -eq 'Office') {
                        $za = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read, $false)
                        try {
                            foreach ($entry in $za.Entries) {
                                if (-not $partRx.IsMatch($entry.FullName)) { continue }
                                if ($entry.Length -gt 262144000) { $state.Err = "Part too large, skipped: $($entry.FullName)"; continue }
                                $es = $entry.Open()
                                try {
                                    $sr = New-Object System.IO.StreamReader($es, [System.Text.Encoding]::UTF8, $true, 65536)
                                    while ($null -ne ($line = $sr.ReadLine())) {
                                        $text = $tagRx.Replace($boundary.Replace($line, ' '), '')
                                        Invoke-LineScan $text $entry.FullName $Detectors $RequiresList
                                    }
                                }
                                finally { $es.Dispose() }
                            }
                        }
                        finally { $za.Dispose() }
                    }
                    else {
                        $binary = $false
                        if ($item.Kind -eq 'Extless') {
                            $buf = New-Object byte[] 8192
                            $n = $fs.Read($buf, 0, $buf.Length)
                            if ($n -gt 0 -and [Array]::IndexOf($buf, [byte]0, 0, $n) -ge 0) { $binary = $true }
                            $null = $fs.Seek(0, [System.IO.SeekOrigin]::Begin)
                        }
                        if (-not $binary) {
                            $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8, $true, 65536)
                            $lineNo = 0
                            while ($null -ne ($line = $sr.ReadLine())) {
                                $lineNo++
                                Invoke-LineScan $line ([string]$lineNo) $Detectors $RequiresList
                            }
                        }
                    }
                }
                finally { $fs.Dispose() }
            }
            catch {
                $Errors.Enqueue([PSCustomObject]@{ Path = $item.Path; Error = (Get-InnerMessage $_) })
            }
            if ($state.Err) { $Errors.Enqueue([PSCustomObject]@{ Path = $item.Path; Error = $state.Err }) }
            foreach ($k in @($acc.Keys)) {
                $v = $acc[$k]
                $Results.Enqueue([PSCustomObject]@{
                        Path = $item.Path; Category = $v.Det.Category; FindingType = $k; Confidence = $v.Det.Confidence
                        Count = $v.Count; FirstLocation = $v.First; Sample = $v.Sample
                        Size = $item.Size; Modified = $item.Modified
                    })
            }
            [System.Threading.Monitor]::Enter($Counters)
            try { $Counters[1]++ } finally { [System.Threading.Monitor]::Exit($Counters) }
        }
    }

    # --- Enumerate and scan ------------------------------------------------------------------
    $queue    = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    $results  = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    $errQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    $counters = [int[]]@(0, 0)
    $rows     = New-Object System.Collections.Generic.List[object]
    $errors   = New-Object System.Collections.Generic.List[object]
    $enumFiles = 0; $queued = 0; $skipSize = 0; $skipCloud = 0; $unreadableDirs = 0
    $maxBytes = [int64]$MaxFileSizeMB * 1MB
    $extlessMax = [Math]::Min($maxBytes, [int64]5MB)
    $cloudMask = 0x1000 -bor 0x400000 -bor 0x40000   # Offline, RecallOnDataAccess, RecallOnOpen
    $reparse = [int][System.IO.FileAttributes]::ReparsePoint
    $pool = $null
    $pending = New-Object System.Collections.Generic.List[object]
    $progressTimer = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
        $pool.Open()
        for ($i = 0; $i -lt $ThrottleLimit; $i++) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            $null = $ps.AddScript($worker.ToString()).AddArgument($queue).AddArgument($results).AddArgument($errQueue).AddArgument($counters).AddArgument($detectors.ToArray()).AddArgument($prelude).AddArgument($requiresList)
            $pending.Add([PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
        }

        $stack = New-Object 'System.Collections.Generic.Stack[string]'
        foreach ($r in $roots) { $stack.Push($r) }
        while ($stack.Count -gt 0) {
            $dirPath = $stack.Pop()
            $di = New-Object System.IO.DirectoryInfo($dirPath)
            $dirNameLower = $di.Name.ToLowerInvariant()

            try {
                foreach ($fi in $di.EnumerateFiles()) {
                    $enumFiles++
                    $lname = $fi.Name.ToLowerInvariant()
                    $ext = [System.IO.Path]::GetExtension($lname)
                    $attr = [int]$fi.Attributes
                    $kind = $null; $nameType = $null
                    if ($nameFull.Contains($lname) -or ($lname -eq 'credentials' -and $dirNameLower -eq '.aws')) { $nameType = 'KeyFile' }
                    elseif ($ext -eq '.kdbx' -or $ext -eq '.kdb') { $nameType = 'CredentialStore' }
                    elseif ($nameExt.Contains($ext)) { $nameType = 'KeyFile' }
                    elseif ($textExt.Contains($ext)) { $kind = 'Text' }
                    elseif ($officeExt.Contains($ext)) { $kind = 'Office' }
                    elseif ($ext.Length -eq 0) { $kind = 'Extless' }

                    if ($nameType) {
                        if ($wantSecret) {
                            $rows.Add([PSCustomObject]@{
                                    Path = $fi.FullName; Category = 'Secret'; FindingType = $nameType; Confidence = 'High'
                                    Count = 1; FirstLocation = 'file name'; Sample = $fi.Name
                                    Size = $fi.Length; Modified = $fi.LastWriteTime
                                })
                        }
                    }
                    elseif ($kind) {
                        if (($attr -band $cloudMask) -ne 0 -and -not $IncludeCloudFiles) { $skipCloud++ }
                        elseif ($fi.Length -eq 0) { }
                        elseif ($fi.Length -gt $maxBytes) { $skipSize++ }
                        elseif ($kind -eq 'Extless' -and $fi.Length -gt $extlessMax) { }
                        else {
                            $queue.Enqueue([PSCustomObject]@{ Path = $fi.FullName; Kind = $kind; Size = $fi.Length; Modified = $fi.LastWriteTime })
                            $queued++
                        }
                    }

                    if ($progressTimer.ElapsedMilliseconds -ge 1000) {
                        Write-Progress -Activity 'Scanning for sensitive data' -Status "$enumFiles files enumerated; $($counters[1]) of $queued content files scanned" -CurrentOperation $dirPath
                        $progressTimer.Restart()
                    }
                }
            }
            catch {
                $unreadableDirs++
                $errors.Add([PSCustomObject]@{ Path = $dirPath; Error = $_.Exception.Message })
            }

            try {
                foreach ($sub in $di.EnumerateDirectories()) {
                    if (([int]$sub.Attributes -band $reparse) -ne 0 -and [SensitiveDataReparse]::IsLinkOrUnknown($sub.FullName)) { continue }
                    $skip = $false
                    $subName = $sub.Name; $subFull = $sub.FullName
                    foreach ($w in $nameWc) { if ($w.IsMatch($subName)) { $skip = $true; break } }
                    if (-not $skip) { foreach ($w in $pathWc) { if ($w.IsMatch($subFull)) { $skip = $true; break } } }
                    if (-not $skip) { $stack.Push($subFull) }
                }
            }
            catch {
                $unreadableDirs++
                $errors.Add([PSCustomObject]@{ Path = $dirPath; Error = $_.Exception.Message })
            }
        }
        $counters[0] = 1

        while ($pending.Count -gt 0) {
            foreach ($p in @($pending | Where-Object { $_.Handle.IsCompleted })) {
                try { $null = $p.PS.EndInvoke($p.Handle) }
                catch { $errors.Add([PSCustomObject]@{ Path = ''; Error = "Worker failed: $($_.Exception.Message)" }) }
                $p.PS.Dispose()
                $null = $pending.Remove($p)
            }
            Write-Progress -Activity 'Scanning for sensitive data' -Status "$enumFiles files enumerated; $($counters[1]) of $queued content files scanned"
            if ($pending.Count -gt 0) { Start-Sleep -Milliseconds 500 }
        }
        Write-Progress -Activity 'Scanning for sensitive data' -Completed
    }
    finally {
        $counters[0] = 1
        foreach ($p in $pending) { $p.PS.Dispose() }
        if ($pool) { $pool.Close(); $pool.Dispose() }
    }

    foreach ($x in $results) { $rows.Add($x) }
    foreach ($x in $errQueue) { $errors.Add($x) }
    $scanned = $counters[1]

    # --- Build the report rows ---------------------------------------------------------------
    $owners = @{}
    $report = foreach ($row in ($rows | Sort-Object Path, FindingType)) {
        if (-not $owners.ContainsKey($row.Path)) {
            $owner = ''
            try { $owner = (Get-Acl -LiteralPath $row.Path -ErrorAction Stop).Owner } catch { $owner = '' }
            $owners[$row.Path] = $owner
        }
        [PSCustomObject][ordered]@{
            Path          = $row.Path
            Category      = $row.Category
            FindingType   = $row.FindingType
            Confidence    = $row.Confidence
            Count         = $row.Count
            FirstLocation = $row.FirstLocation
            Sample        = $row.Sample
            SizeKB        = [Math]::Round($row.Size / 1KB, 1)
            LastWriteTime = $row.Modified
            Owner         = $owners[$row.Path]
        }
    }
    $report = @($report)

    # --- Write CSVs --------------------------------------------------------------------------
    $outDir = Split-Path -Path $OutputPath -Parent
    try {
        if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { $null = New-Item -Path $outDir -ItemType Directory -Force -ErrorAction Stop }
        if ($report.Count -gt 0) { $report | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop }
        else { Set-Content -LiteralPath $OutputPath -Value '"Path","Category","FindingType","Confidence","Count","FirstLocation","Sample","SizeKB","LastWriteTime","Owner"' -Encoding UTF8 -ErrorAction Stop }
    }
    catch { throw "Could not write the report to ${OutputPath}: $($_.Exception.Message)" }

    $errorPath = $null
    if ($errors.Count -gt 0) {
        $errorPath = [System.IO.Path]::ChangeExtension($OutputPath, $null).TrimEnd('.') + '-errors.csv'
        try { $errors | Select-Object Path, Error | Export-Csv -LiteralPath $errorPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop }
        catch { Write-Warning "Could not write the error list to ${errorPath}: $($_.Exception.Message)"; $errorPath = $null }
    }
    $sw.Stop()

    # --- Summary -----------------------------------------------------------------------------
    Write-Host ''
    Write-Host 'Sensitive data scan summary' -ForegroundColor Cyan
    Write-Host "  Roots:               $($roots -join '; ')"
    Write-Host "  Files enumerated:    $enumFiles"
    Write-Host "  Content scanned:     $scanned"
    Write-Host "  Skipped:             $skipSize over $MaxFileSizeMB MB, $skipCloud cloud-only, $($errors.Count) unreadable ($unreadableDirs folders)"
    Write-Host "  Findings:            $($report.Count) rows in $(@($report | Select-Object -ExpandProperty Path -Unique).Count) files"
    foreach ($g in @($report | Group-Object FindingType, Confidence | Sort-Object Name)) {
        Write-Host ('    {0,-40} {1}' -f $g.Name, $g.Count)
    }
    $top = @($report | Group-Object { [System.IO.Path]::GetDirectoryName($_.Path) } | Sort-Object Count -Descending | Select-Object -First 10)
    if ($top.Count -gt 0) {
        Write-Host '  Top folders by findings:'
        foreach ($t in $top) { Write-Host ('    {0,5}  {1}' -f $t.Count, $t.Name) }
    }
    Write-Host "  Elapsed:             $($sw.Elapsed.ToString('hh\:mm\:ss'))"
    Write-Host "  Report:              $OutputPath"
    if ($errorPath) { Write-Host "  Errors:              $errorPath" }
    Write-Host 'This report maps where sensitive data lives. Restrict access to it and delete it after triage.' -ForegroundColor Yellow

    if ($PassThru) { $report }
}

Set-Alias -Name piiscan -Value Find-SensitiveData
