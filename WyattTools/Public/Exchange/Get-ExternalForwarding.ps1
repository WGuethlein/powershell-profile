<#
.SYNOPSIS
    Finds mailboxes that forward mail to external addresses.
.DESCRIPTION
    Checks mailbox-level forwarding (ForwardingSmtpAddress, ForwardingAddress) and, unless
    -SkipInboxRules is used, inbox rules (enabled, disabled and hidden) with ForwardTo, RedirectTo or
    ForwardAsAttachmentTo actions. A target is external when its domain is not an accepted domain
    of the tenant. Legacy DN (EX:) targets are internal. By default only external forwards are
    returned. Connects to Exchange Online if needed.
.PARAMETER Mailbox
    Limit the scan to these mailboxes (identity, UPN or SMTP address). Default is all mailboxes.
.PARAMETER SkipInboxRules
    Check mailbox-level forwarding only. Much faster on large tenants.
.PARAMETER IncludeInternal
    Also return forwards to internal targets.
.PARAMETER Export
    Write results to ExternalForwarding_yyyyMMdd_HHmm.csv in the configured export directory.
.EXAMPLE
    Get-ExternalForwarding -SkipInboxRules | Format-Table
.EXAMPLE
    Get-ExternalForwarding -Mailbox jdoe@contoso.com -IncludeInternal
.EXAMPLE
    Get-ExternalForwarding -Export
.NOTES
    Name: Get-ExternalForwarding
    Version: 1.1.0
    Author: WGuethlein
    Date: 2026-10-04
    Prerequisites: ExchangeOnlineManagement module (EXO V3)
#>
function Get-ExternalForwarding {
    [CmdletBinding()]
    param(
        [string[]]$Mailbox,

        [switch]$SkipInboxRules,

        [switch]$IncludeInternal,

        [switch]$Export
    )

    # Pulls an address out of a recipient string. Returns the address, the raw string for
    # EX: legacyDN entries (internal), or $null when nothing usable is found.
    $extractAddress = {
        param([string]$Text)
        if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
        # Rule recipients look like: "Name" [SMTP:user@domain.com]
        if ($Text -match '\[SMTP:([^\]]+)\]') { return $Matches[1].Trim() }
        # Internal recipients are shown as legacyExchangeDN: "Name" [EX:/o=...] or EX:/o=...
        if ($Text -match 'EX:/') { return $Text.Trim() }
        # Fallback: plain email address (also handles a leading 'smtp:' prefix).
        if ($Text -match "[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}") { return $Matches[0] }
        return $null
    }

    $null = Connect-M365 -Exchange

    # Accepted domains, case-insensitive lookup.
    $domains = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($d in Get-AcceptedDomain) { $null = $domains.Add([string]$d.DomainName) }

    # Anything without an @ (EX: legacyDN) is internal.
    $isExternal = {
        param([string]$Address)
        if ($Address -notlike '*@*') { return $false }
        $domain = $Address.Substring($Address.LastIndexOf('@') + 1)
        return (-not $domains.Contains($domain))
    }

    $props = 'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward'
    if ($Mailbox) {
        # A bad identity warns and is skipped so the rest of the list still runs.
        $mailboxes = foreach ($m in $Mailbox) {
            try { Get-EXOMailbox -Identity $m -Properties $props -ErrorAction Stop }
            catch { Write-Warning "Mailbox '$m' not found: $($_.Exception.Message)" }
        }
    }
    else {
        Write-Verbose 'Retrieving all mailboxes.'
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties $props
    }
    $mailboxes = @($mailboxes)

    $showInternal = $IncludeInternal.IsPresent
    $results = New-Object System.Collections.Generic.List[object]
    $addResult = {
        param($Mbx, $Source, $RuleName, $RuleEnabled, $Action, $Target)
        $ext = & $isExternal $Target
        if ($ext -or $showInternal) {
            $results.Add([pscustomobject]@{
                Mailbox                    = $Mbx.PrimarySmtpAddress
                Source                     = $Source
                RuleName                   = $RuleName
                RuleEnabled                = $RuleEnabled
                Action                     = $Action
                Target                     = $Target
                External                   = [bool]$ext
                DeliverToMailboxAndForward = $Mbx.DeliverToMailboxAndForward
            })
        }
    }

    $i = 0
    foreach ($mbx in $mailboxes) {
        $i++
        Write-Progress -Activity 'Scanning forwarding' -Status "$i of $($mailboxes.Count): $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($i / [math]::Max($mailboxes.Count, 1)) * 100)
        try {
            # (a) ForwardingSmtpAddress, stored as 'smtp:user@domain.com'
            if ($mbx.ForwardingSmtpAddress) {
                $target = & $extractAddress ([string]$mbx.ForwardingSmtpAddress)
                if ($target) { & $addResult $mbx 'MailboxForwardingSmtp' $null $null 'Forward' $target }
            }

            # (b) ForwardingAddress is a recipient identity; resolve it (may be a contact or mail user)
            if ($mbx.ForwardingAddress) {
                # Own try/catch so a lookup failure does not skip this mailbox's inbox-rule scan;
                # fall back to the raw value so the forward is still recorded.
                $fwdTarget = [string]$mbx.ForwardingAddress
                try {
                    $rcpt = Get-EXORecipient -Identity $fwdTarget -ErrorAction Stop
                    $fwdTarget = [string]$rcpt.PrimarySmtpAddress
                }
                catch {
                    Write-Warning "Could not resolve ForwardingAddress '$fwdTarget' on '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
                }
                & $addResult $mbx 'MailboxForwardingAddress' $null $null 'Forward' $fwdTarget
            }

            # (c) Inbox rules, enabled and disabled. -IncludeHidden also returns hidden rules,
            # a known attacker technique for concealing forwarding.
            if (-not $SkipInboxRules) {
                foreach ($rule in @(Get-InboxRule -Mailbox ([string]$mbx.PrimarySmtpAddress) -IncludeHidden -ErrorAction Stop)) {
                    foreach ($action in 'ForwardTo', 'RedirectTo', 'ForwardAsAttachmentTo') {
                        foreach ($entry in @($rule.$action)) {
                            if ($null -eq $entry -or "$entry" -eq '') { continue }
                            $target = & $extractAddress ([string]$entry)
                            if (-not $target) { $target = [string]$entry }
                            & $addResult $mbx 'InboxRule' $rule.Name $rule.Enabled $action $target
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to check '$($mbx.PrimarySmtpAddress)': $_"
        }
    }
    Write-Progress -Activity 'Scanning forwarding' -Completed

    $external = @($results | Where-Object { $_.External }).Count
    $color = 'Green'
    if ($external -gt 0) { $color = 'Yellow' }
    Write-Host "Mailboxes scanned: $($mailboxes.Count). External forwards found: $external" -ForegroundColor $color

    if ($Export) {
        $path = Join-Path (Get-ExportDirectory) ('ExternalForwarding_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmm'))
        $results | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Host "Exported to $path" -ForegroundColor Cyan
    }

    $results
}

Set-Alias -Name extfwd -Value Get-ExternalForwarding
