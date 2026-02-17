<#
.SYNOPSIS
    Renames a user account in Active Directory and Azure AD.

.DESCRIPTION
    This function updates a user's UserPrincipalName in Active Directory and automatically
    updates all related attributes. It then syncs to Azure AD and optionally updates the
    Azure AD UPN and Exchange routing address.

.PARAMETER OldUPN
    The current UserPrincipalName of the user (e.g., jsmith@dlz.com).

.PARAMETER NewUPN
    The new UserPrincipalName for the user (e.g., jjohnson@dlz.com).

.PARAMETER SkipAzureAD
    Skip the Azure AD UserPrincipalName update step.

.PARAMETER SkipExchange
    Skip the Exchange Remote Routing Address update step.

.EXAMPLE
    Rename-ADUser -OldUPN "jsmith@dlz.com" -NewUPN "jjohnson@dlz.com"
    Renames user and updates all systems

.EXAMPLE
    Rename-ADUser -OldUPN "jsmith@dlz.com" -NewUPN "jjohnson@dlz.com" -SkipExchange
    Renames user but skips Exchange updates

.NOTES
    Name:          Rename-ADUser
    Version:       2.0
    Author:        WGuethlein
    Date:          2026-02-16
    Prerequisites: 
    - Active Directory module
    - Admin rights on AD
    - Microsoft.Graph.Users module (if not skipping Azure AD)
    - ExchangeOnlineManagement module (if not skipping Exchange)
#>

function Rename-ADUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Current UserPrincipalName (e.g., jsmith@dlz.com)")]
        [string]$OldUPN,
        
        [Parameter(Mandatory = $true, HelpMessage = "New UserPrincipalName (e.g., jjohnson@dlz.com)")]
        [string]$NewUPN,
        
        [Parameter(Mandatory = $false, HelpMessage = "Skip Azure AD UPN update")]
        [switch]$SkipAzureAD,
        
        [Parameter(Mandatory = $false, HelpMessage = "Skip Exchange Remote Routing Address update")]
        [switch]$SkipExchange
    )
    
    # Variables
    $domainController = "COLOAD101.dlzcorp.com"
    
    # Import Active Directory module
    Import-Module ActiveDirectory
    
    # Extract the new surname from the new UPN
    $newUsername = ($NewUPN -split '@')[0]
    $oldUsername = ($OldUPN -split '@')[0]
    
    # Try to determine the surname change
    # Assuming format like firstname.lastname or firstnamelastname
    if ($newUsername -match '\.') {
        $newSurname = ($newUsername -split '\.')[1]
        $newSurname = (Get-Culture).TextInfo.ToTitleCase($newSurname)
    }
    else {
        Write-Host "Cannot automatically determine surname from UPN." -ForegroundColor Yellow
        $newSurname = Read-Host "Please enter the new surname"
        $newSurname = (Get-Culture).TextInfo.ToTitleCase($newSurname)
    }
    
    # Retrieve the user account by UPN
    $user = Get-ADUser -Server $domainController -Filter "UserPrincipalName -eq '$OldUPN'" -Properties CN, Surname, DisplayName, SamAccountName, UserPrincipalName, EmailAddress, MailNickname, ProxyAddresses
    
    if ($user -eq $null) {
        Write-Host "User with UPN '$OldUPN' not found." -ForegroundColor Red
        return
    }
    
    # Extract current values
    $oldCn = $user.CN
    $oldSurname = $user.Surname
    $oldEmail = $user.EmailAddress
    $oldDisplayname = $user.DisplayName
    $oldSamAccountName = $user.SamAccountName
    $oldMailNickname = $user.MailNickname
    
    # Confirm user
    if ($($host.UI.PromptForChoice($oldDisplayname, "`nIs this the correct user?", @("&Yes", "&No"), 1)) -ne 0) {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }
    
    #### Update CN
    if ($oldCn -match "(?i)$oldSurname") {
        $newCn = $oldCn -replace "(?i)$oldSurname", $newSurname
    }
    else {
        Write-Host "Old Surname '$oldSurname' not found in CommonName '$oldCn'." -ForegroundColor Yellow
        $newCn = Read-Host "Please enter new Common Name"
    }
    
    # Validate New UPN
    if (Get-ADUser -Server $domainController -Filter "UserPrincipalName -eq '$NewUPN'" -ErrorAction SilentlyContinue) {
        Write-Host "`nERROR: UserPrincipalName '$NewUPN' is already in use.`n" -ForegroundColor Red
        return
    }
    
    #### Update SamAccountName and MailNickname
    $newSamAccountName = $newUsername.ToLower()
    $newMailNickname = $newUsername.ToLower()
    
    # Validate New SamAccountName
    if (Get-ADUser -Server $domainController -Filter "SamAccountName -eq '$newSamAccountName'" -ErrorAction SilentlyContinue) {
        Write-Host "`nERROR: SamAccountName '$newSamAccountName' is already in use.`n" -ForegroundColor Red
        return
    }
    
    # Validate New MailNickname
    if (Get-ADUser -Server $domainController -Properties MailNickname -Filter "MailNickname -eq '$newMailNickname'" -ErrorAction SilentlyContinue) {
        Write-Host "`nERROR: MailNickname '$newMailNickname' is already in use.`n" -ForegroundColor Red
        return
    }
    
    #### Update Email
    $domain = ($NewUPN -split '@')[1]
    $newEmail = $NewUPN
    $newPrimarySMTP = "SMTP:" + $newEmail
    
    # Create new remote routing address
    $newRemoteRoutingAddress = "smtp:" + $newSamAccountName + "@DLZ807.mail.onmicrosoft.com"
    
    # Preserve the original primary SMTP address
    $oldPrimarySMTP = @($user.ProxyAddresses | Where-Object { $_ -clike "SMTP:*" })
    
    # Collect existing proxy addresses (excluding the outdated primary SMTP)
    $oldProxyAddresses = @($user.ProxyAddresses | Where-Object { !($_ -clike "SMTP:*") }) | ForEach-Object { "$_" }
    $newProxyAddresses = @($oldProxyAddresses + $oldPrimarySMTP.ToLower() + $newPrimarySMTP + $newRemoteRoutingAddress) | ForEach-Object { "$_" }
    
    #### Update DisplayName - capitalize first letter
    if (($oldDisplayname -match "(?i)$oldSurname[ ,](?i)") -or ($oldDisplayname.endswith($oldSurname))) {
        $newDisplayName = $oldDisplayname -replace $oldSurname, $newSurname
    }
    else {
        Write-Host "Old surname '$oldSurname' not found in DisplayName '$oldDisplayname'." -ForegroundColor Yellow
        $newDisplayName = Read-Host "Please enter new display name"
        $newDisplayName = (Get-Culture).TextInfo.ToTitleCase($newDisplayName)
    }
    
    # Truncate for display
    $truncate = {
        param ($str) 
        if ($str.Length -gt 50) { $str.Substring(0, 50) + "..." }
        else { $str }
    }
    
    #### Show changes before committing
    Write-Host "`n`nPROPOSED CHANGES:"
    Write-Host "`nOld Values:"
    Write-Host " - Old Surname: $oldSurname"
    Write-Host " - Old MailNickname: $oldMailNickname"
    Write-Host " - Old Display name: $oldDisplayname"
    Write-Host " - Old UserPrincipalName: $OldUPN"
    Write-Host " - Old Email Address: $oldEmail"
    Write-Host " - Old ProxyAddresses:"
    Write-Host "   - $(& $truncate $oldPrimarySMTP)"
    $oldProxyAddresses | ForEach-Object { Write-Host "   - $(& $truncate $_)" }
    
    Write-Host "`nNew Values:"
    Write-Host " + New Surname: $newSurname"
    Write-Host " + New MailNickname: $newMailNickname"
    Write-Host " + New Display name: $newDisplayName"
    Write-Host " + New UserPrincipalName: $NewUPN"
    Write-Host " + New Email Address: $newEmail"
    Write-Host " + New ProxyAddresses:"
    $newProxyAddresses | ForEach-Object { Write-Host "   + $(& $truncate $_)" }
    
    if ($($host.UI.PromptForChoice($null, "`nIs this correct?", @("&Yes", "&No"), 1)) -eq 0) {
        Write-Host "`n`nConfirmed. Making requested changes..."
        
        # Make AD changes on specified domain controller
        Set-ADUser -Server $domainController -Identity $user.SamAccountName -Surname $newSurname
        Set-ADUser -Server $domainController -Identity $user.SamAccountName -UserPrincipalName $NewUPN
        Set-ADUser -Server $domainController -Identity $user.SamAccountName -EmailAddress $newEmail
        Set-ADUser -Server $domainController -Identity $user.SamAccountName -DisplayName $newDisplayName
        Set-ADUser -Server $domainController -Identity $user.SamAccountName -Replace @{ proxyAddresses = $newProxyAddresses }
        Set-ADUser -Server $domainController -Identity $user.SamAccountName -Replace @{ mailNickname = $newMailNickname }
        Set-ADUser -Server $domainController -Identity $user.SamAccountName -SamAccountName $newSamAccountName -ErrorAction SilentlyContinue
        Rename-ADObject -Server $domainController -Identity $user.DistinguishedName -NewName $newCn
        
        Write-Host "`nActive Directory changes complete." -ForegroundColor Green
        
        # Trigger AD Sync
        Write-Host "`nTriggering Azure AD Connect sync..." -ForegroundColor Cyan
        try {
            Start-ADSync
        }
        catch {
            Write-Host "Warning: Could not trigger AD Sync automatically." -ForegroundColor Yellow
        }
        
        # Wait for sync
        Write-Host "`nWaiting 60 seconds for AD Sync to propagate to Azure..." -ForegroundColor Cyan
        Start-Sleep -Seconds 60
        
        # Update Azure AD UPN (if not skipped)
        if (-not $SkipAzureAD) {
            Write-Host "`nUpdating Azure AD UserPrincipalName..." -ForegroundColor Yellow
            
            # Check if already connected to Microsoft Graph
            $context = Get-MgContext -ErrorAction SilentlyContinue
            if (-not $context) {
                Write-Host "Not connected to Microsoft Graph. Please connect first with:" -ForegroundColor Yellow
                Write-Host "  Connect-MgGraph -Scopes 'User.ReadWrite.All'" -ForegroundColor Cyan
                Write-Host "`nSkipping Azure AD update. Run 'Update-AzureADUserUPN' manually after connecting." -ForegroundColor Yellow
            }
            else {
                try {
                    Update-AzureADUserUPN -OldUPN $OldUPN -NewUPN $NewUPN
                }
                catch {
                    Write-Host "Warning: Azure AD update failed - $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "`nSkipped Azure AD update" -ForegroundColor Gray
        }
        
        # Update Exchange (if not skipped)
        if (-not $SkipExchange) {
            Write-Host "`nUpdating Exchange Remote Routing Address..." -ForegroundColor Yellow
            
            # Check if connected to Exchange Online
            $exoSession = Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened" }
            if (-not $exoSession) {
                Write-Host "Not connected to Exchange Online. Please connect first with:" -ForegroundColor Yellow
                Write-Host "  Connect-ExchangeOnline" -ForegroundColor Cyan
                Write-Host "`nSkipping Exchange update. Run 'Update-ExchangeRemoteRoutingAddress' manually after connecting." -ForegroundColor Yellow
            }
            else {
                try {
                    Update-ExchangeRemoteRoutingAddress -Identity $newEmail -NewRemoteRoutingAddress $newRemoteRoutingAddress
                }
                catch {
                    Write-Host "Warning: Exchange update failed - $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "`nSkipped Exchange update" -ForegroundColor Gray
        }
        
        # Final summary
        Write-Host "`n==================================" -ForegroundColor Green
        Write-Host "Rename Process Complete!" -ForegroundColor Green
        Write-Host "==================================`n" -ForegroundColor Green
        
        Write-Host "Remaining Manual Steps:" -ForegroundColor Yellow
        Write-Host "  1. Modify Zoom/Bluebeam/Autodesk accounts to reflect these changes"
        Write-Host "  2. Ensure user can logon with new credentials: $NewUPN"
        Write-Host "  3. Have user sign out of all services and sign back in with new credentials"
        Write-Host "  4. User should run 'Reset-OneDriveSync' on their machine to clear sync errors"
        Write-Host "`n"
    }
    else {
        Write-Host "`nOperation cancelled." -ForegroundColor Yellow
    }
}

function Reset-OneDriveSync {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    
    Write-Host "OneDrive Sync Reset Utility" -ForegroundColor Cyan
    Write-Host "============================`n"
    
    # Find OneDrive executable
    $oneDrivePath = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
    
    if (-not (Test-Path $oneDrivePath)) {
        Write-Host "ERROR: OneDrive not found at expected location." -ForegroundColor Red
        Write-Host "Expected: $oneDrivePath" -ForegroundColor Yellow
        return
    }
    
    try {
        if ($PSCmdlet.ShouldProcess("OneDrive", "Reset sync connection")) {
            Write-Host "Shutting down OneDrive..." -ForegroundColor Cyan
            & $oneDrivePath /shutdown
            Start-Sleep -Seconds 3
            
            Write-Host "Restarting OneDrive..." -ForegroundColor Cyan
            Start-Process $oneDrivePath
            
            Write-Host "`nSUCCESS: OneDrive has been reset" -ForegroundColor Green
            Write-Host "`nNext Steps:" -ForegroundColor Yellow
            Write-Host "  1. OneDrive should open and prompt you to sign in"
            Write-Host "  2. Sign in with your new credentials"
            Write-Host "  3. Your files will begin syncing again"
        }
    }
    catch {
        Write-Host "`nERROR: Failed to reset OneDrive" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "`nManual steps:" -ForegroundColor Yellow
        Write-Host "  1. Right-click OneDrive icon in system tray"
        Write-Host "  2. Click 'Pause syncing' then 'Resume syncing'"
    }
}

function Update-ExchangeRemoteRoutingAddress {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "User's email address or identity")]
        [string]$Identity,
        
        [Parameter(Mandatory = $true, HelpMessage = "New remote routing address (e.g., newname@tenant.mail.onmicrosoft.com)")]
        [string]$NewRemoteRoutingAddress
    )
    
    # Check if Exchange Management Shell is available
    if (-not (Get-Command Get-RemoteMailbox -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: Exchange Management Shell not found." -ForegroundColor Red
        Write-Host "This function requires Exchange Management Shell or Exchange Online PowerShell module." -ForegroundColor Yellow
        Write-Host "Connect to Exchange Online with: Connect-ExchangeOnline" -ForegroundColor Yellow
        return
    }
    
    try {
        Connect-ExchangeOnline
        # Get the remote mailbox
        Write-Host "Searching for remote mailbox: $Identity..." -ForegroundColor Cyan
        $mailbox = Get-RemoteMailbox -Identity $Identity -ErrorAction Stop
        
        if ($null -eq $mailbox) {
            Write-Host "`nERROR: Remote mailbox not found for: $Identity" -ForegroundColor Red
            return
        }
        
        Write-Host "`nFound mailbox:" -ForegroundColor Green
        Write-Host "  Display Name: $($mailbox.DisplayName)"
        Write-Host "  Primary SMTP: $($mailbox.PrimarySmtpAddress)"
        Write-Host "  Current Remote Routing Address: $($mailbox.RemoteRoutingAddress)"
        
        # Show proposed change
        Write-Host "`nProposed Change:" -ForegroundColor Yellow
        Write-Host "  Old Remote Routing Address: $($mailbox.RemoteRoutingAddress)" -ForegroundColor Red
        Write-Host "  New Remote Routing Address: $NewRemoteRoutingAddress" -ForegroundColor Green
        
        if ($PSCmdlet.ShouldProcess($Identity, "Update Remote Routing Address to $NewRemoteRoutingAddress")) {
            # Update the remote routing address
            Write-Host "`nUpdating Remote Routing Address..." -ForegroundColor Cyan
            Set-RemoteMailbox -Identity $Identity -RemoteRoutingAddress $NewRemoteRoutingAddress -ErrorAction Stop
            
            Write-Host "`nSUCCESS: Remote Routing Address updated" -ForegroundColor Green
            Write-Host "New address: $NewRemoteRoutingAddress" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "`nERROR: Failed to update Remote Routing Address" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Update-AzureADUserUPN {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Current UserPrincipalName in Azure AD")]
        [string]$OldUPN,
        
        [Parameter(Mandatory = $true, HelpMessage = "New UserPrincipalName for Azure AD")]
        [string]$NewUPN
    )
    
    # Check if Microsoft.Graph module is installed
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
        Write-Host "ERROR: Microsoft.Graph.Users module not found." -ForegroundColor Red
        Write-Host "Install it with: Install-Module Microsoft.Graph.Users -Scope CurrentUser" -ForegroundColor Yellow
        return
    }
    
    try {
        # Import required modules
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        
        # Connect to Microsoft Graph (will prompt for authentication if not already connected)
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome -ErrorAction Stop
        
        # Find the user by old UPN
        Write-Host "Searching for user with UPN: $OldUPN..." -ForegroundColor Cyan
        $azureUser = Get-MgUser -Filter "userPrincipalName eq '$OldUPN'" -ErrorAction Stop
        
        if ($null -eq $azureUser) {
            Write-Host "`nERROR: User not found in Azure AD with UPN: $OldUPN" -ForegroundColor Red
            Write-Host "Note: AD Sync may not have completed yet. Wait a few minutes and try again." -ForegroundColor Yellow
            return
        }
        
        Write-Host "`nFound user: $($azureUser.DisplayName)" -ForegroundColor Green
        Write-Host "  Current UPN: $($azureUser.UserPrincipalName)"
        Write-Host "  Object ID: $($azureUser.Id)"
        
        # Show proposed change
        Write-Host "`nProposed Change:" -ForegroundColor Yellow
        Write-Host "  Old UPN: $OldUPN" -ForegroundColor Red
        Write-Host "  New UPN: $NewUPN" -ForegroundColor Green
        
        if ($PSCmdlet.ShouldProcess($OldUPN, "Update Azure AD UserPrincipalName to $NewUPN")) {
            # Update the UPN
            Write-Host "`nUpdating UserPrincipalName in Azure AD..." -ForegroundColor Cyan
            Update-MgUser -UserId $azureUser.Id -UserPrincipalName $NewUPN -ErrorAction Stop
            
            Write-Host "`nSUCCESS: Azure AD UserPrincipalName updated to $NewUPN" -ForegroundColor Green
            
            Write-Host "`nNext Steps:" -ForegroundColor Yellow
            Write-Host "  1. User must sign out of all Microsoft services (Teams, Outlook, OneDrive, etc.)"
            Write-Host "  2. User should sign back in with the new UPN: $NewUPN"
            Write-Host "  3. It may take a few minutes for changes to propagate across all services"
        }
    }
    catch [Microsoft.Graph.PowerShell.Authentication.AuthenticationException] {
        Write-Host "`nERROR: Authentication failed" -ForegroundColor Red
        Write-Host "Please ensure you have the appropriate permissions in Azure AD." -ForegroundColor Yellow
    }
    catch {
        Write-Host "`nERROR: Failed to update Azure AD UPN" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}