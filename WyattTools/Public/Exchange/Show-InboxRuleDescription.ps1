<#
.SYNOPSIS
    Lists inbox rules and their plain-text descriptions for Exchange mailboxes.
.DESCRIPTION
    Wrapper around the Exchange Get-InboxRule cmdlet. It is intentionally named differently,
    because a function named Get-InboxRule would shadow the cmdlet and call itself. Works in
    Exchange Online (EXO V3) and the Exchange 2019 Management Shell. If no Exchange session is
    found, connects to Exchange Online automatically.
.PARAMETER Mailbox
    Mailbox identity: UPN, alias, SMTP address, etc. Accepts pipeline input, including objects
    from Get-Mailbox.
.PARAMETER IncludeHidden
    Also return hidden rules, such as the Junk E-mail rule.
.EXAMPLE
    Show-InboxRuleDescription -Mailbox jdoe@contoso.com
.EXAMPLE
    Get-Mailbox jdoe | ibr | Format-List
.EXAMPLE
    ibr jdoe@contoso.com -IncludeHidden | Where-Object Enabled
    Show only the enabled rules, including hidden ones, for one mailbox.
.EXAMPLE
    'a@contoso.com', 'b@contoso.com' | ibr | Sort-Object Mailbox, Priority | Export-Csv .\rules.csv -NoTypeInformation
    Collect the rules for several mailboxes and save them to a CSV.
.NOTES
    Name: Show-InboxRuleDescription
    Version: 2.0.0
    Author: WGuethlein
    Date: 2026-10-02
    Prerequisites: ExchangeOnlineManagement module (or an existing Exchange session)
#>
function Show-InboxRuleDescription {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Identity', 'PrimarySmtpAddress')]
        [string]$Mailbox,

        [switch]$IncludeHidden
    )

    begin {
        # No Exchange session loaded (EXO exposes cmdlets as proxy functions): connect.
        # Connect-M365 handles runas sessions (browser sign-in instead of WAM).
        if (-not (Get-Command -Name Get-InboxRule -ErrorAction SilentlyContinue)) {
            $null = Connect-M365 -Exchange
        }
    }

    process {
        try {
            Get-InboxRule -Mailbox $Mailbox -IncludeHidden:$IncludeHidden -ErrorAction Stop |
                Select-Object @{ Name = 'Mailbox'; Expression = { $Mailbox } },
                              Name, Enabled, Priority,
                              @{ Name = 'Description'; Expression = { "$($_.Description)".Trim() } }
        }
        catch {
            Write-Error "Failed to get inbox rules for '$Mailbox': $_"
        }
    }
}

Set-Alias -Name ibr -Value Show-InboxRuleDescription
Set-Alias -Name gir -Value Show-InboxRuleDescription
