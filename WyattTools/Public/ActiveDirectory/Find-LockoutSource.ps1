<#
.SYNOPSIS
    Finds which computer caused account lockouts (event 4740) on the PDC emulator.
.DESCRIPTION
    Reads Security event 4740 from the PDC emulator for the last N hours and parses TargetUserName
    and TargetDomainName (the caller computer name in 4740) by name from the event XML. If -User is
    given, results are filtered to that account and the current LockedOut state and lockoutTime
    are shown. Returns objects; reports a friendly message when no events exist.
.PARAMETER User
    Optional SamAccountName to filter on.
.PARAMETER Hours
    How far back to search. Default 24.
.PARAMETER Server
    Domain controller to query. Default: PdcEmulator from config, else the domain PDC emulator.
.EXAMPLE
    Find-LockoutSource -User jdoe -Hours 4
.EXAMPLE
    Find-LockoutSource
.NOTES
    Name: Find-LockoutSource
    Version: 1.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: ActiveDirectory module, rights to read the Security log on the DC
#>
function Find-LockoutSource {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$User,

        [Parameter()]
        [ValidateRange(1, 8760)]
        [int]$Hours = 24,

        [Parameter()]
        [string]$Server
    )

    Assert-Module -Name ActiveDirectory

    if ([string]::IsNullOrWhiteSpace($Server)) {
        $Server = (Get-WyattConfig).PdcEmulator
        if ([string]::IsNullOrWhiteSpace($Server)) { $Server = (Get-ADDomain).PDCEmulator }
    }

    if ($User) {
        try {
            # Resolve email/UPN/SamAccountName; 4740 events record the SamAccountName.
            $resolved = Resolve-ADUserIdentity -User $User -Properties LockedOut, lockoutTime | Select-Object -First 1
            if (-not $resolved.ADUser) { throw $resolved.Error }
            $adUser = $resolved.ADUser
            $User = $adUser.SamAccountName
            $lockTime = $null
            if ($adUser.lockoutTime) { $lockTime = [datetime]::FromFileTime([int64]$adUser.lockoutTime) }
            $color = 'Green'
            if ($adUser.LockedOut) { $color = 'Red' }
            Write-Host "$($adUser.SamAccountName): LockedOut=$($adUser.LockedOut) lockoutTime=$lockTime" -ForegroundColor $color
        }
        catch {
            Write-Warning "Could not read AD user '$User': $($_.Exception.Message)"
        }
    }

    Write-Verbose "Querying 4740 events on $Server for the last $Hours hour(s)"
    $filter = @{ LogName = 'Security'; Id = 4740; StartTime = (Get-Date).AddHours(-$Hours) }

    try {
        $events = @(Get-WinEvent -ComputerName $Server -FilterHashtable $filter -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -like '*No events were found*') {
            Write-Host "No lockout events (4740) found on $Server in the last $Hours hour(s)." -ForegroundColor Yellow
            return
        }
        Write-Error "Failed to read Security log on ${Server}: $($_.Exception.Message)"
        return
    }

    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        if ($User -and $data['TargetUserName'] -ne $User) { continue }

        [PSCustomObject]@{
            TimeCreated      = $e.TimeCreated
            User             = $data['TargetUserName']
            CallerComputer   = $data['TargetDomainName']
            DomainController = $e.MachineName
        }
    }
}
