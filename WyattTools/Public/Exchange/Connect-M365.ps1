<#
.SYNOPSIS
    Connects to Microsoft Graph and/or Exchange Online, skipping services already connected.
.DESCRIPTION
    Idempotent connector. Graph is considered connected when Get-MgContext exists and holds every
    requested scope. Exchange Online (EXO V3, REST based) is considered connected when
    Get-ConnectionInformation reports a connection in the 'Connected' state. With neither -Graph
    nor -Exchange, both services are handled. Returns an object with the connected accounts.
.PARAMETER Graph
    Connect to Microsoft Graph.
.PARAMETER Exchange
    Connect to Exchange Online.
.PARAMETER Scopes
    Graph scopes to request. Defaults to GraphScopes from the WyattTools config.
.PARAMETER Disconnect
    Disconnect the selected services instead of connecting.
.PARAMETER DisableWAM
    Sign in with the browser instead of Web Account Manager (WAM). Applied automatically when
    the shell runs as a different account than the console user (runas), because WAM fails
    there with "A specified logon session does not exist".
.EXAMPLE
    Connect-M365
.EXAMPLE
    Connect-M365 -Exchange
.EXAMPLE
    Connect-M365 -Graph -Scopes 'User.Read.All','Group.Read.All'
.NOTES
    Name: Connect-M365
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: Microsoft.Graph.Authentication and/or ExchangeOnlineManagement modules
#>
function Connect-M365 {
    [CmdletBinding()]
    param(
        [switch]$Graph,

        [switch]$Exchange,

        [string[]]$Scopes,

        [switch]$Disconnect,

        [switch]$DisableWAM
    )

    # Neither service named: do both.
    if (-not $Graph -and -not $Exchange) { $Graph = $true; $Exchange = $true }

    if ($Disconnect) {
        if ($Graph -and (Get-Command -Name Disconnect-MgGraph -ErrorAction SilentlyContinue)) {
            $null = Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-Host 'Graph: disconnected' -ForegroundColor Yellow
        }
        if ($Exchange -and (Get-Command -Name Disconnect-ExchangeOnline -ErrorAction SilentlyContinue)) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host 'Exchange: disconnected' -ForegroundColor Yellow
        }
        return
    }

    $graphAccount = $null
    $exoAccount   = $null

    $noWam = $DisableWAM.IsPresent
    if (-not $noWam -and (Test-RunAsSession)) {
        $noWam = $true
        Write-Host 'runas session detected: signing in with the browser instead of WAM.' -ForegroundColor Yellow
    }

    if ($Graph) {
        Assert-Module -Name Microsoft.Graph.Authentication
        if (-not $Scopes) { $Scopes = @((Get-WyattConfig).GraphScopes) }

        $ctx = Get-MgContext
        # -notcontains is case-insensitive, which matches how Graph treats scope names.
        $missing = @($Scopes | Where-Object { $null -eq $ctx -or @($ctx.Scopes) -notcontains $_ })
        if ($ctx -and $missing.Count -eq 0) {
            Write-Host "Graph: already connected as $($ctx.Account)" -ForegroundColor Green
        }
        else {
            $mgParams = @{ NoWelcome = $true; ErrorAction = 'Stop' }
            if ($Scopes) { $mgParams.Scopes = $Scopes }
            if ($noWam) {
                # Newer Graph modules can turn WAM off (saved per user); older ones can't, so fall
                # back to device-code sign-in, which doesn't use WAM.
                $optCmd = Get-Command -Name Set-MgGraphOption -ErrorAction SilentlyContinue
                if ($optCmd -and $optCmd.Parameters.ContainsKey('DisableLoginByWAM')) {
                    Set-MgGraphOption -DisableLoginByWAM $true
                }
                else {
                    Write-Host 'Graph: this module version cannot disable WAM; using device code sign-in.' -ForegroundColor Yellow
                    $mgParams.UseDeviceCode = $true
                }
            }
            Connect-MgGraph @mgParams
            $ctx = Get-MgContext
            Write-Host "Graph: connected as $($ctx.Account)" -ForegroundColor Green
        }
        $graphAccount = $ctx.Account
    }

    if ($Exchange) {
        Assert-Module -Name ExchangeOnlineManagement

        $conn = Get-ConnectionInformation -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Connected' } | Select-Object -First 1
        if ($conn) {
            Write-Host "Exchange: already connected as $($conn.UserPrincipalName)" -ForegroundColor Green
        }
        else {
            $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
            if ($noWam) {
                # -DisableWAM exists in ExchangeOnlineManagement 3.7.0+ (the first WAM version).
                if ((Get-Command -Name Connect-ExchangeOnline).Parameters.ContainsKey('DisableWAM')) {
                    $exoParams.DisableWAM = $true
                }
            }
            Connect-ExchangeOnline @exoParams
            $conn = Get-ConnectionInformation -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq 'Connected' } | Select-Object -First 1
            Write-Host "Exchange: connected as $($conn.UserPrincipalName)" -ForegroundColor Green
        }
        if ($conn) { $exoAccount = $conn.UserPrincipalName }
    }

    [pscustomobject]@{
        Graph    = $graphAccount
        Exchange = $exoAccount
    }
}
