# Create the alias
Set-Alias -Name Reset-PwdExp -Value Reset-PasswordExpiration

. "Get-PwdExp.ps1"

# The function it points to
function Reset-PasswordExpiration {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    
    try {
        
        $user = Get-ADUser -Identity $Username -Properties PasswordLastSet

        if ($user.PasswordNeverExpires) {
            Write-Output "Password never expires for user: $Username"
        } else {
            
            $user.pwdLastSet = 0
            Set-ADUser -Instance $user
            $user.pwdLastSet = -1
            Set-ADUser -Instance $user
            Write-Output "Password expires on: "
	    Get-PwdExp $Username    
        }
    }
    catch {
        Write-Error "Error retrieving password information for $Username : $($_.Exception.Message)"
    }
}