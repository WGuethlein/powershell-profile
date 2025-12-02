


# The function it points to
function Get-UserPasswordExpiration {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    
    try {
        $user = Get-ADUser -Identity $Username -Properties PasswordLastSet, PasswordNeverExpires
        
        if ($user.PasswordNeverExpires) {
            Write-Output "Password never expires for user: $Username"
        } else {
            $maxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge
            $passwordExpiration = $user.PasswordLastSet.AddDays($maxPasswordAge.Days)
            
            Write-Output "Password expires on: $($passwordExpiration.ToString('yyyy-MM-dd HH:mm:ss'))"
            
            $daysUntilExpiration = ($passwordExpiration - (Get-Date)).Days
            if ($daysUntilExpiration -lt 0) {
                Write-Output "Password expired $([Math]::Abs($daysUntilExpiration)) days ago"
            } else {
                Write-Output "Days until expiration: $daysUntilExpiration"
            }
        }
    }
    catch {
        Write-Error "Error retrieving password information for $Username : $($_.Exception.Message)"
    }
}

# Create the alias
Set-Alias -Name Get-PwdExp -Value Get-UserPasswordExpiration