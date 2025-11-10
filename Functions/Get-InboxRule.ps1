# Function to Base64 encode a string
function Get-InboxRule {
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]$Inbox
    )
    
    Get-InboxRule -Mailbox $Inbox | Select-Object -ExpandProperty Description | Format-List
    return $EncodedText
}

# Create an alias for the function
Set-Alias -Name ibr -Value Get-InboxRule