# WyattTools configuration template. Copy to config.psd1 (gitignored) and fill in real values.
@{
    # Azure AD Connect server used by Start-ADSync.
    AADConnectServer = 'SYNCSERVER01'


    # Base DN for user accounts.
    ADBaseDn         = 'OU=Accounts,DC=contoso,DC=com'

    # Friendly OU name -> distinguished name (used by Get-ADUserReport).
    OUs              = @{
        Active   = 'OU=Active,OU=Accounts,DC=contoso,DC=com'
        Departed = 'OU=Departed,OU=Accounts,DC=contoso,DC=com'
        CR       = 'OU=Users,OU=Branch,OU=Accounts,DC=contoso,DC=com'
        India    = 'OU=India,OU=Accounts,DC=contoso,DC=com'
    }

    # Blank = auto-detect via (Get-ADDomain).PDCEmulator.
    PdcEmulator      = ''

    # Days without logon/password change before an account is considered stale.
    StaleDays        = 90

    # Microsoft Graph delegated scopes.
    GraphScopes      = @('User.Read.All', 'Group.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All')

    # License group -> SKU part number(s) it should grant (used by Get-GroupLicenseGap).
    LicenseGroups    = @{
        'LIC-Office365-E3' = 'ENTERPRISEPACK'
        'LIC-EMS-E3'       = 'EMS'
    }

    # Default export directory. Blank = current location.
    ExportDirectory  = ''

    # Root folders scanned by Update-FileAccessIndex (UNC or DFS paths).
    FileAccessRoots  = @('\\contoso.com\files$\Projects', '\\contoso.com\files$\Shared')

    # Where the file access index is stored. Blank = %LOCALAPPDATA%\WyattTools\FileAccessIndex.
    # Set to a restricted UNC share so a scheduled scan and your shell share one index.
    FileAccessIndexPath = ''
}
