# Function to Base64 encode a string
function Convert-ToBase64 {
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]$Text
    )
    
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $EncodedText = [Convert]::ToBase64String($Bytes)
    return $EncodedText
}

# Create an alias for the function
Set-Alias -Name B64E -Value Convert-ToBase64