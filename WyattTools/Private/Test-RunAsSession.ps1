<#
    Test-RunAsSession (private)
    Returns $true when this shell runs as a different account than the user signed in to the
    console - i.e. it was started with runas. Web Account Manager (WAM) sign-in needs the
    signed-in user's logon session, so it fails there ("A specified logon session does not
    exist"). Returns $false when it can't tell (e.g. RDP sessions report no console user).
#>
function Test-RunAsSession {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $consoleUser = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName
    }
    catch {
        Write-Verbose "Could not read console user: $($_.Exception.Message)"
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($consoleUser)) { return $false }

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    # -ne is case-insensitive, matching DOMAIN\user comparisons.
    return ($consoleUser -ne $currentUser)
}
