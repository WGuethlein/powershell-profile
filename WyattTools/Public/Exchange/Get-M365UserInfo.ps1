<#
.SYNOPSIS
    Returns a consolidated Microsoft 365 account summary for one or more users.
.DESCRIPTION
    Cloud counterpart of Get-ADUserInfo. Resolves a UPN, email address, or on-prem SamAccountName
    to an Entra ID user and returns one object with identity, status, directory sync, sign-in,
    MFA methods, licenses, and aliases; with -Mailbox it adds Exchange Online mailbox details.
    Licenses show where each one comes from ('direct' or the assigning group) and any assignment
    error (for example CountViolation = out of seats) is appended and counted in LicenseErrors.
    Input containing '@' is used as the UPN, with a fallback lookup on the mail attribute. Input
    without '@' is resolved to a UPN through Active Directory (ActiveDirectory module required).
    LastSignIn is lastSuccessfulSignInDateTime, falling back to the later of the interactive and
    non-interactive sign-ins. Sign-in data needs AuditLog.Read.All and Entra ID P1; if it is
    denied the sign-in fields read 'unavailable'. MFA methods need UserAuthenticationMethod.Read.All;
    if denied MfaMethods reads 'unavailable (needs UserAuthenticationMethod.Read.All)'.
    Required Graph scopes: User.Read.All, Organization.Read.All or Directory.Read.All (SKU names),
    Group.Read.All or GroupMember.Read.All (license group names), AuditLog.Read.All,
    UserAuthenticationMethod.Read.All.
.PARAMETER Identity
    UPN, email address, or SamAccountName. Accepts pipeline input.
.PARAMETER Mailbox
    Also connect to Exchange Online and add MailboxType, Forwarding, and LitigationHold.
.EXAMPLE
    Get-M365UserInfo jdoe@contoso.com
.EXAMPLE
    m365info jdoe
.EXAMPLE
    'a@contoso.com', 'b@contoso.com' | Get-M365UserInfo
.EXAMPLE
    Get-M365UserInfo jdoe@contoso.com -Mailbox | Format-List
.NOTES
    Name: Get-M365UserInfo
    Version: 1.0.0
    Author: WGuethlein
    Date: 2026-10-04
    Prerequisites: Microsoft.Graph.Authentication module; ExchangeOnlineManagement for -Mailbox;
                   ActiveDirectory module only for SamAccountName input
#>
function Get-M365UserInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('UserPrincipalName', 'User', 'Mail')]
        [string[]]$Identity,

        [switch]$Mailbox
    )

    begin {
        $null = Connect-M365 -Graph
        if ($Mailbox) { $null = Connect-M365 -Exchange }

        $base = 'https://graph.microsoft.com/v1.0'

        # Invoke-MgGraphRequest throws on HTTP errors; the status code is only reliably in the
        # message text (PS7: "404 (Not Found)", PS 5.1: "NotFound"/"Forbidden") or the Graph
        # error code in ErrorDetails, so match on both.
        $errText = {
            param($ErrorRecord)
            $t = [string]$ErrorRecord.Exception.Message
            if ($ErrorRecord.ErrorDetails) { $t += ' ' + $ErrorRecord.ErrorDetails.Message }
            $t
        }
        $isNotFound = { param($e) (& $errText $e) -match '404|NotFound|Request_ResourceNotFound|does not exist' }
        $isDenied   = { param($e) (& $errText $e) -match '403|401|Forbidden|Unauthorized|Authorization_RequestDenied|Insufficient privileges|AccessDenied|premium' }

        $getGraph = {
            param([string]$Uri)
            Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop
        }

        $getUserRaw = {
            param([string]$K, [bool]$IncludeSignIn)
            $sel = $select
            if ($IncludeSignIn) { $sel += ',signInActivity' }
            & $getGraph ("$base/users/$([uri]::EscapeDataString($K))?`$select=$sel")
        }

        # skuId -> part number. licenseAssignmentStates only carries the skuId.
        $partBySkuId = @{}
        $uri = "$base/subscribedSkus"
        while ($uri) {
            $page = & $getGraph $uri
            foreach ($s in @($page.value)) { $partBySkuId[[string]$s.skuId] = [string]$s.skuPartNumber }
            $uri = $page.'@odata.nextLink'
        }

        $groupNames = @{}            # group id -> display name, cached per run
        $state = @{ SignIn = $true; Warned = $false }
        $warnedMfa = $false
        $adChecked = $false
        $adAvailable = $false

        $select = 'id,displayName,userPrincipalName,mail,accountEnabled,department,jobTitle,createdDateTime,' +
                  'onPremisesSyncEnabled,onPremisesLastSyncDateTime,assignedLicenses,licenseAssignmentStates,' +
                  'proxyAddresses,usageLocation'

        $mfaNames = @{
            microsoftAuthenticatorAuthenticationMethod = 'Authenticator app'
            phoneAuthenticationMethod                  = 'Phone'
            fido2AuthenticationMethod                  = 'FIDO2 key'
            windowsHelloForBusinessAuthenticationMethod = 'Windows Hello'
            softwareOathAuthenticationMethod           = 'Software OTP'
            temporaryAccessPassAuthenticationMethod    = 'Temporary Access Pass'
            emailAuthenticationMethod                  = 'Email'
            platformCredentialAuthenticationMethod     = 'Platform credential'
        }
    }

    process {
        foreach ($raw in $Identity) {
            $id = $raw.Trim()
            if ($id -eq '') { continue }

            # --- Resolve to a UPN ---
            $key = $id
            if (-not $id.Contains('@')) {
                if (-not $adChecked) {
                    $adChecked = $true
                    $adAvailable = [bool](Get-Module -ListAvailable -Name ActiveDirectory)
                }
                if (-not $adAvailable) {
                    Write-Error "'$id' has no '@' and the ActiveDirectory module is not available. Provide a UPN or email address."
                    continue
                }
                $resolved = @(Resolve-ADUserIdentity -User $id)[0]
                if ($null -eq $resolved.ADUser -or -not $resolved.ADUser.UserPrincipalName) {
                    Write-Error "Could not resolve '$id' to a UPN in AD: $($resolved.Error)"
                    continue
                }
                $key = $resolved.ADUser.UserPrincipalName
            }

            # --- Fetch the user; signInActivity is dropped if Graph denies it ---
            $state.SignIn = $true
            $user = $null
            $notFound = $false
            $fetchUser = {
                param([string]$K)
                try { return (& $getUserRaw $K $true) }
                catch {
                    if ((& $isNotFound $_) -or -not (& $isDenied $_)) { throw }
                    $state.SignIn = $false
                    if (-not $state.Warned) {
                        Write-Warning 'Sign-in data unavailable (needs AuditLog.Read.All and Entra ID P1). Continuing without it.'
                        $state.Warned = $true
                    }
                    return (& $getUserRaw $K $false)
                }
            }
            try { $user = & $fetchUser $key }
            catch {
                if (& $isNotFound $_) { $notFound = $true }
                else { Write-Error "Graph lookup failed for '$id': $(& $errText $_)"; continue }
            }

            # Not found by UPN: try the mail attribute.
            if ($notFound) {
                try {
                    $safe = [uri]::EscapeDataString("mail eq '$($key.Replace("'", "''"))'")
                    $found = @((& $getGraph "$base/users?`$filter=$safe&`$select=id").value)
                    if ($found.Count -eq 1) { $user = & $fetchUser ([string]$found[0].id) }
                }
                catch { Write-Verbose "Mail lookup failed for '$key': $(& $errText $_)" }
            }
            if ($null -eq $user) {
                Write-Error "User not found in Entra ID: $id"
                continue
            }

            # --- Sign-in ---
            $lastSignIn = 'unavailable'
            $lastInteractive = 'unavailable'
            if ($state.SignIn) {
                $lastSignIn = $null
                $lastInteractive = $null
                $sa = $user.signInActivity
                if ($sa) {
                    if ($sa.lastSuccessfulSignInDateTime) { $lastSignIn = ([datetime]$sa.lastSuccessfulSignInDateTime).ToLocalTime() }
                    else {
                        # Older accounts have no successful-sign-in value: use the later of the other two.
                        $cands = @($sa.lastSignInDateTime, $sa.lastNonInteractiveSignInDateTime |
                                Where-Object { $_ } | ForEach-Object { ([datetime]$_).ToLocalTime() })
                        if ($cands.Count -gt 0) { $lastSignIn = ($cands | Sort-Object -Descending)[0] }
                    }
                    if ($sa.lastSignInDateTime) { $lastInteractive = ([datetime]$sa.lastSignInDateTime).ToLocalTime() }
                }
            }

            # --- MFA methods ---
            $mfa = $null
            try {
                $m = & $getGraph "$base/users/$($user.id)/authentication/methods"
                $types = foreach ($method in @($m.value)) {
                    $t = ([string]$method.'@odata.type') -replace '^#microsoft\.graph\.', ''
                    if ($t -eq 'passwordAuthenticationMethod') { continue }
                    if ($mfaNames.ContainsKey($t)) { $mfaNames[$t] } else { $t }
                }
                $mfa = (@($types) | Sort-Object -Unique) -join ', '
            }
            catch {
                if (& $isDenied $_) {
                    $mfa = 'unavailable (needs UserAuthenticationMethod.Read.All)'
                    if (-not $warnedMfa) {
                        Write-Warning 'MFA methods unavailable (needs UserAuthenticationMethod.Read.All).'
                        $warnedMfa = $true
                    }
                }
                else { $mfa = "unavailable ($(& $errText $_))" }
            }

            # --- Licenses ---
            $licenses = New-Object System.Collections.Generic.List[string]
            $errorList = New-Object System.Collections.Generic.List[string]
            foreach ($st in @($user.licenseAssignmentStates)) {
                $skuId = [string]$st.skuId
                $part = if ($partBySkuId.ContainsKey($skuId)) { $partBySkuId[$skuId] } else { $skuId }
                if ($st.assignedByGroup) {
                    $gid = [string]$st.assignedByGroup
                    if (-not $groupNames.ContainsKey($gid)) {
                        try { $groupNames[$gid] = [string](& $getGraph "$base/groups/${gid}?`$select=displayName").displayName }
                        catch { $groupNames[$gid] = $gid; Write-Verbose "Group lookup failed for ${gid}: $_" }
                    }
                    $via = "group: $($groupNames[$gid])"
                }
                else { $via = 'direct' }
                $line = "$part ($via)"
                if ($st.error -and $st.error -ne 'None') {
                    $line += " ERROR: $($st.error)"
                    $errorList.Add([string]$st.error)
                }
                elseif ($st.state -and $st.state -ne 'Active') { $line += " [$($st.state)]" }
                $licenses.Add($line)
            }

            # Aliases: smtp: entries (lowercase = secondary) except the primary SMTP address.
            $aliases = @($user.proxyAddresses | Where-Object { $_ -cmatch '^smtp:' } | ForEach-Object { $_.Substring(5) })

            $out = [ordered]@{
                DisplayName       = $user.displayName
                UserPrincipalName = $user.userPrincipalName
                Mail              = $user.mail
                Enabled           = $user.accountEnabled
                Department        = $user.department
                Title             = $user.jobTitle
                Created           = if ($user.createdDateTime) { ([datetime]$user.createdDateTime).ToLocalTime() } else { $null }
                SyncedFromAD      = [bool]$user.onPremisesSyncEnabled
                LastDirSync       = if ($user.onPremisesLastSyncDateTime) { ([datetime]$user.onPremisesLastSyncDateTime).ToLocalTime() } else { $null }
                LastSignIn        = $lastSignIn
                LastInteractiveSignIn = $lastInteractive
                MfaMethods        = $mfa
                Licenses          = [string[]]@($licenses | Sort-Object)
                LicenseErrors     = ($errorList | Select-Object -Unique) -join ', '
                UsageLocation     = $user.usageLocation
                Aliases           = $aliases -join ', '
            }

            # --- Mailbox (only with -Mailbox) ---
            if ($Mailbox) {
                try {
                    $mbx = Get-EXOMailbox -Identity $user.userPrincipalName -Properties RecipientTypeDetails, ForwardingSmtpAddress, LitigationHoldEnabled -ErrorAction Stop
                    $out.MailboxType = [string]$mbx.RecipientTypeDetails
                    $out.Forwarding = [string]$mbx.ForwardingSmtpAddress
                    $out.LitigationHold = [bool]$mbx.LitigationHoldEnabled
                }
                catch {
                    Write-Verbose "Mailbox lookup failed for $($user.userPrincipalName): $_"
                    $out.MailboxType = 'no mailbox'
                    $out.Forwarding = $null
                    $out.LitigationHold = $null
                }
            }

            [pscustomobject]$out
        }
    }
}

Set-Alias -Name m365info -Value Get-M365UserInfo
