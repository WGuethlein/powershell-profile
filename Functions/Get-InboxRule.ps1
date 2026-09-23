<#
.SYNOPSIS
    Lists inbox rules and their plain-text descriptions for Exchange mailboxes.
.DESCRIPTION
    Wrapper around the Exchange Get-InboxRule cmdlet. It is intentionally named
    differently, because a function named Get-InboxRule would shadow the cmdlet
    and call itself. Works in Exchange Online (EXO V3) and the Exchange 2019
    Management Shell. You must already be connected.
.PARAMETER Mailbox
    Mailbox identity: UPN, alias, SMTP address, etc. Accepts pipeline input,
    including objects from Get-Mailbox.
.PARAMETER IncludeHidden
    Also return hidden rules, such as the Junk E-mail rule.
.EXAMPLE
    Show-InboxRuleDescription -Mailbox jdoe@dlzcorp.com
.EXAMPLE
    Get-Mailbox jdoe | ibr | Format-List
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
        # Fail early if no Exchange session is loaded (EXO exposes cmdlets as proxy functions)
        if (-not (Get-Command -Name Get-InboxRule -ErrorAction SilentlyContinue)) {
            Import-Module ExchangeOnlineManagement
			Connect-ExchangeOnline -ShowBanner:$False
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

# Short alias for interactive use
Set-Alias -Name ibr -Value Show-InboxRuleDescription
Set-Alias -Name gir -Value Show-InboxRuleDescription