<#
.SYNOPSIS
    Shows what file access an AD group grants, or who has access to a folder, from the file access index.
.DESCRIPTION
    Reads the index built by Update-FileAccessIndex; it never touches the file servers.
    -Group lists every folder where the group (or a group it is nested in) appears on the ACL, with
    the access level, whether it is allowed or denied, and how many folders below have inheritance
    blocked (access does not flow into those). -Path lists every permission that applies to one
    folder by walking up from it to the scanned root, stopping at the first folder that blocks
    inheritance. Only share-independent NTFS permissions are covered; share-level permissions are
    not in the index, and effective access is the more restrictive of the two.
.PARAMETER Group
    AD group: sAMAccountName, name or distinguished name.
.PARAMETER Path
    Folder to inspect. UNC or DFS path, or a mapped drive letter (translated to its network path).
    Must be under a root that was scanned.
.PARAMETER IndexPath
    Folder holding the index. Default: FileAccessIndexPath in the config; if blank,
    %LOCALAPPDATA%\WyattTools\FileAccessIndex.
.EXAMPLE
    faccess 'Proj-Finance-RW'
    Every folder in the index where Proj-Finance-RW (or a group containing it) grants or denies access.
.EXAMPLE
    Get-FileAccess -Group 'Proj-Finance-RW' | Format-Table Path, Access, Type, Via, AppliesTo
    The same list with the AppliesTo column added.
.EXAMPLE
    faccess -Path '\\contoso.com\files$\files\Projects\Alpha\Drawings'
    Everyone with access to that folder, where each permission was set, and whether it is inherited.
.EXAMPLE
    faccess -Path X:\Projects\Alpha -IndexPath '\\fs01.contoso.com\FileIndex$'
    A mapped drive path, using an index on a shared location.
.NOTES
    Name: Get-FileAccess
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-19
    Prerequisites: An index from Update-FileAccessIndex. ActiveDirectory module for -Group.
    -Group output shows a list by default; pipe to Format-Table for one row per ACE (all properties remain available).
    Share-level permissions are not included (Panzura filers cannot be queried for them).
#>
function Get-FileAccess {
    [CmdletBinding(DefaultParameterSetName = 'Group')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Group')]
        [ValidateNotNullOrEmpty()]
        [string]$Group,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [string]$IndexPath
    )

    $index = Import-FileAccessIndex -IndexPath (Get-FileAccessIndexPath -IndexPath $IndexPath)
    Write-Host ("File access index scanned {0:yyyy-MM-dd HH:mm}" -f $index.ScanTime) -ForegroundColor DarkGray
    if (((Get-Date) - $index.ScanTime).TotalDays -gt 14) {
        Write-Warning "The file access index is more than 14 days old. Run Update-FileAccessIndex to refresh it."
    }

    # Sets the default display columns while keeping every property available.
    $setDisplay = {
        param($Object, [string[]]$Names)
        $set = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', $Names)
        Add-Member -InputObject $Object -MemberType MemberSet -Name PSStandardMembers -Value ([System.Management.Automation.PSMemberInfo[]]@($set)) -Force
    }
    $denyFirst = @{ Expression = { if ($_.Type -eq 'Deny') { 0 } else { 1 } } }

    if ($PSCmdlet.ParameterSetName -eq 'Group') {
        Assert-Module -Name ActiveDirectory

        # Resolve the group: sAMAccountName or DN first, then by name.
        $adGroup = $null
        try { $adGroup = Get-ADGroup -Identity $Group -ErrorAction Stop }
        catch {
            $safe = $Group.Replace("'", "''")
            $adGroup = @(Get-ADGroup -Filter "Name -eq '$safe'" -ErrorAction SilentlyContinue) | Select-Object -First 1
        }
        if (-not $adGroup) { throw "Group not found: $Group" }

        # Groups this one is nested in (transitively), via the in-chain matching rule.
        # DN characters special in LDAP filters are hex-escaped; backslash goes first.
        $dn = $adGroup.DistinguishedName.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
        $parents = @(Get-ADGroup -LDAPFilter "(member:1.2.840.113556.1.4.1941:=$dn)")

        $sidMap = @{}
        $sidMap[$adGroup.SID.Value] = @{ Name = $adGroup.Name; Via = 'Direct' }
        foreach ($p in $parents) { $sidMap[$p.SID.Value] = @{ Name = $p.Name; Via = 'Nested' } }

        # Distinct paths with inheritance blocked, for the ProtectedBelow count.
        $blockedPaths = @($index.Rows | Where-Object { $_.InheritanceBlocked -eq 'True' } | ForEach-Object { $_.Path } | Sort-Object -Unique)

        $display = 'Path', 'Access', 'Type', 'GrantedTo', 'Via', 'ProtectedBelow'
        $results = @(foreach ($row in $index.Rows) {
                if (-not $row.Sid -or -not $sidMap.ContainsKey($row.Sid)) { continue }
                $prefix = $row.Path + '\'
                $below = @($blockedPaths | Where-Object { $_.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) }).Count
                $obj = [pscustomobject][ordered]@{
                    Path               = $row.Path
                    Access             = ConvertTo-FileRightsLevel -Mask ([int64]$row.Rights)
                    Type               = $row.Type
                    GrantedTo          = $row.Identity
                    Via                = $sidMap[$row.Sid].Via
                    AppliesTo          = ConvertTo-FileAppliesTo -InheritanceFlags $row.InheritanceFlags -PropagationFlags $row.PropagationFlags
                    InheritanceBlocked = ($row.InheritanceBlocked -eq 'True')
                    ProtectedBelow     = $below
                }
                & $setDisplay $obj $display
                $obj
            })

        if ($results.Count -eq 0) {
            Write-Host ("{0} (and its {1} parent groups) appears on no ACL in the index: it grants no file access under the scanned roots, or only through broad groups such as Everyone." -f $adGroup.Name, $parents.Count) -ForegroundColor Yellow
            return
        }
        $results | Sort-Object $denyFirst, Path
        return
    }

    # -Path mode: normalize to the form the index uses.
    $target = $Path.Trim().TrimEnd('\')
    if ($target -match '^[A-Za-z]:') {
        $drive = Get-PSDrive -Name $target.Substring(0, 1) -PSProvider FileSystem -ErrorAction SilentlyContinue
        if ($drive -and $drive.DisplayRoot) {
            $target = $drive.DisplayRoot.TrimEnd('\') + $target.Substring(2)
        }
    }
    if (-not $target.StartsWith('\\')) {
        $target = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($target).TrimEnd('\')
    }

    # Longest index root that equals the path or is a parent of it.
    $ignoreCase = [System.StringComparison]::OrdinalIgnoreCase
    $root = $null
    foreach ($r in $index.Roots) {
        if ($target.Equals($r, $ignoreCase) -or $target.StartsWith($r + '\', $ignoreCase)) {
            if (-not $root -or $r.Length -gt $root.Length) { $root = $r }
        }
    }
    if (-not $root) { throw "'$target' is not under any scanned root (roots: $($index.Roots -join ', '))." }

    $byPath = New-Object 'System.Collections.Generic.Dictionary[string, object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $index.Rows) {
        if ($row.Root -ne $root) { continue }
        if (-not $byPath.ContainsKey($row.Path)) { $byPath[$row.Path] = New-Object System.Collections.Generic.List[object] }
        $byPath[$row.Path].Add($row)
    }

    # Walk from the target up to the root, stopping after a folder that blocks inheritance.
    $display = 'Identity', 'Access', 'Type', 'SetAt', 'AppliesTo'
    $results = New-Object System.Collections.Generic.List[object]
    $folder = $target
    $parentOfTarget = $target.Substring(0, [Math]::Max($target.LastIndexOf('\'), 0))
    while ($true) {
        if ($byPath.ContainsKey($folder)) {
            $blocked = $false
            foreach ($row in $byPath[$folder]) {
                if ($row.InheritanceBlocked -eq 'True') { $blocked = $true }
                if (-not $row.Sid) { continue }
                $isTarget = $folder.Equals($target, $ignoreCase)
                if ($isTarget) {
                    if ($row.PropagationFlags -like '*InheritOnly*') { continue }
                }
                else {
                    if ($row.InheritanceFlags -notlike '*ContainerInherit*') { continue }
                    if ($row.PropagationFlags -like '*NoPropagateInherit*' -and -not $folder.Equals($parentOfTarget, $ignoreCase)) { continue }
                }
                $obj = [pscustomobject][ordered]@{
                    Identity  = $row.Identity
                    Access    = ConvertTo-FileRightsLevel -Mask ([int64]$row.Rights)
                    Type      = $row.Type
                    AppliesTo = ConvertTo-FileAppliesTo -InheritanceFlags $row.InheritanceFlags -PropagationFlags $row.PropagationFlags
                    SetAt     = $folder
                    Inherited = ((-not $isTarget) -or ($row.IsInherited -eq 'True'))
                }
                & $setDisplay $obj $display
                $results.Add($obj)
            }
            if ($blocked) { break }
        }
        if ($folder.Equals($root, $ignoreCase)) { break }
        $cut = $folder.LastIndexOf('\')
        if ($cut -lt 0) { break }
        $folder = $folder.Substring(0, $cut)
    }

    # Folders the scan could not read mean the results may be incomplete.
    foreach ($e in $index.Errors) {
        if ($target.Equals($e.Path, $ignoreCase) -or $target.StartsWith($e.Path + '\', $ignoreCase)) {
            Write-Warning "The scan could not read '$($e.Path)' ($($e.Operation)): results may be incomplete."
            break
        }
    }

    $results | Sort-Object $denyFirst, Identity
}

Set-Alias -Name faccess -Value Get-FileAccess
