# WyattTools examples

Worked examples for every WyattTools command, from the simple case to combined and piped uses.
Names used here (jdoe, contoso.com, 'VPN-Users', server01) are placeholders. The same examples
are in each command's help: `Get-Help <command> -Examples`.

- [Active Directory](#active-directory)
- [Exchange / Microsoft 365](#exchange--microsoft-365)
- [Network](#network)
- [Utility](#utility)
- [Git](#git)

## Active Directory

### `Add-ADGroupUser`
Adds one user, several users, or a list from a file to an AD group, skipping anyone already a direct member.
```powershell
# Simple case
Add-ADGroupUser -User jdoe -Group 'VPN-Users'
# More complex: preview a CSV load and see who would be skipped
Add-ADGroupUser -File C:\Temp\users.csv -Group 'VPN-Users' -WhatIf -Verbose
# More complex: one column from a multi-column CSV, piped in
Import-Csv C:\Temp\users.csv | Select-Object -ExpandProperty Email | Add-ADGroupUser -Group 'VPN-Users'
```
Gotcha: only direct membership is checked. A user who is a member through a nested group is still added directly. The file must hold one identifier per line; for a multi-column CSV, use `Import-Csv` and pipe one column.

### `Remove-ADGroupUser`
Removes one user, several users, or a list from an AD group, only if they are direct members.
```powershell
# Simple case
Remove-ADGroupUser -User jdoe -Group 'VPN-Users' -WhatIf
# More complex: remove a list with no per-user prompt
Remove-ADGroupUser -File C:\Temp\users.csv -Group 'VPN-Users' -Confirm:$false
# More complex: preview, with skipped (not direct member) users shown
Remove-ADGroupUser -File C:\Temp\users.csv -Group 'VPN-Users' -WhatIf -Verbose
```
Gotcha: removal prompts for every user by default (ConfirmImpact High). A user who is only a nested member is counted as "not a direct member" and left alone.

### `Copy-ADGroupMembership`
Adds a target user to every group a source user is directly in (never removes anything).
```powershell
# Simple case
Copy-ADGroupMembership jdoe asmith -WhatIf
# More complex: skip groups, then review only the failures
Copy-ADGroupMembership -SourceUser jdoe -TargetUser asmith -ExcludeGroup 'Domain Users','VPN-Users' | Where-Object Status -eq 'Failed'
# More complex: per-group outcome table using email addresses
Copy-ADGroupMembership jdoe@contoso.com asmith@contoso.com | Format-Table
```
Gotcha: passing `-ExcludeGroup` replaces the default of `Domain Users`; include it in your list if you still want it skipped. Status values are Added, AlreadyMember, Excluded, Failed, WhatIf.

### `Compare-ADGroupMembers`

Answers "who is in this group but not that one" style questions, including nested members.

How the switches combine, always in this order no matter how you type them:

1. Start with the users in `-Group`, plus the users in every `-Or` group.
2. Keep only users who are also in every `-And` group.
3. Drop anyone in any `-Not` group.

```powershell
# Users in VPN-Users who are not in MFA-Enrolled
Compare-ADGroupMembers -Group 'VPN-Users' -Not 'MFA-Enrolled'

# Senior leaders who have NEITHER Copilot license group (several -Not groups = "in none of them")
Compare-ADGroupMembers -Group 'Senior-Leaders' -Not 'LIC-Copilot-A', 'LIC-Copilot-B' | Format-Table

# Senior leaders who are in BOTH license groups (double-licensed)
Compare-ADGroupMembers -Group 'Senior-Leaders' -And 'LIC-Copilot-A', 'LIC-Copilot-B'

# Senior leaders or directors, who are remote staff, and not MFA enrolled
Compare-ADGroupMembers -Group 'Senior-Leaders' -Or 'Directors' -And 'Remote-Staff' -Not 'MFA-Enrolled'

# Direct members only, filtered to disabled accounts, saved to CSV
Compare-ADGroupMembers -Group 'VPN-Users' -Not 'MFA-Enrolled' -DirectOnly -Export |
    Where-Object { -not $_.Enabled }
```

Gotcha: `-Not 'A' -Or 'B'` does NOT mean "not in A or B". `-Or` adds B's users to the
starting set, so you get (Group or B) not in A, which pulls in people who were never in
`-Group`. To exclude several groups, list them all after `-Not`: `-Not 'A', 'B'`. The
command prints a warning when `-Or` and `-Not` are used together. Check the summary line
it prints (for example `Senior-Leaders, not in LIC-Copilot-A or LIC-Copilot-B: 3 users`)
to confirm it ran the logic you meant.

### `Get-ADUserInfo` (`adinfo`)
Shows one user's account status, password dates, last logon, manager, and groups.
```powershell
# Simple case
adinfo jdoe
# More complex: compare several users in one table
'jdoe','asmith' | adinfo | Select-Object SamAccountName, Enabled, LockedOut, PasswordExpires, LastLogon
# More complex: is this user directly in a group?
(adinfo jdoe).MemberOf -contains 'VPN-Users'
# More complex: pipe AD objects in and keep locked-out accounts
Get-ADUser -Filter "Department -eq '1234'" | adinfo | Where-Object LockedOut
```
Gotcha: `MemberOf` is direct groups only. `LastLogon` can lag by up to 14 days. `PasswordExpires` is empty when the password never expires.

### `Get-ADUserDepartment`
Looks up the department for one user or a list of users.
```powershell
# Simple case
Get-ADUserDepartment -User jdoe@contoso.com
# More complex: look up a list and save it
Get-ADUserDepartment -File C:\Temp\users.csv | Export-Csv C:\Temp\departments.csv -NoTypeInformation
# More complex: which identifiers did not resolve?
Get-ADUserDepartment -File C:\Temp\users.csv | Where-Object Department -eq '<NOT FOUND>'
```
Gotcha: the input file is one identifier per line (email, UPN, or SamAccountName), not a multi-column CSV. Users with no department show `<none>`.

### `Get-ADUsersByDept`
Lists all enabled users in a department (wildcards allowed); `-Export` saves a CSV.
```powershell
# Simple case
Get-ADUsersByDept 1234
# More complex: how many users per department in a range?
Get-ADUsersByDept '5*' | Group-Object Department | Sort-Object Count -Descending
# More complex: save the full list but show only managers
Get-ADUsersByDept -Department '12*' -Export | Where-Object JobTitle -like '*Manager*'
```
Gotcha: `*` is a wildcard; other special characters are escaped. Disabled users are never returned.

### `Get-ADUserReport`
Lists users from one of the configured OUs (Active, Departed, CR, India); `-Export` saves a CSV.
```powershell
# Simple case
Get-ADUserReport -Ou Active | Format-Table
# More complex: active users with no manager
Get-ADUserReport -Ou Active -Properties SamAccountName,Name,Title,Department,Manager | Where-Object { -not $_.Manager }
# More complex: trimmed columns to CSV
Get-ADUserReport -Ou India -Properties SamAccountName,Enabled,Title -Export
```
Gotcha: only immediate children of the OU are queried (no sub-OUs). `Manager` shows the manager's SamAccountName; `-Properties` replaces the default column list.

### `Get-UserPasswordExpiration` (`Get-PwdExp`)
Shows when a user's password expires (by username, UPN, or email), honoring fine-grained password policies.
```powershell
# Simple case
Get-PwdExp jdoe
# More complex: who expires in the next two weeks?
Get-Content C:\Temp\users.txt | Get-PwdExp | Where-Object { $_.DaysRemaining -le 14 } | Sort-Object DaysRemaining
# More complex: expired passwords for a department
Get-ADUser -Filter "Department -eq '1234'" | Get-PwdExp | Where-Object Expired
```
Gotcha: users whose password never expires have empty `ExpiresOn` and `DaysRemaining`, so a `-le 14` filter drops them silently.

### `Get-StaleAccounts`
Lists enabled users and computers that haven't logged on in a set number of days (default 90).
```powershell
# Simple case
Get-StaleAccounts
# More complex: longest-inactive users first
Get-StaleAccounts -Type User -Days 180 | Sort-Object DaysInactive -Descending | Select-Object -First 25
# More complex: where are the stale computers?
Get-StaleAccounts -Type Computer | Group-Object { $_.DistinguishedName -replace '^CN=[^,]+,' } | Sort-Object Count -Descending
# More complex: year-stale, saved to CSV, never-logged-on only on screen
Get-StaleAccounts -Days 365 -IncludeDisabled -Export | Where-Object { $null -eq $_.LastLogon }
```
Gotcha: LastLogonTimestamp replicates with up to about 14 days of lag, so don't use `-Days` below 14. Accounts that never logged on are judged by creation date.

### `Find-LockoutSource`
Finds which computer locked out an account by reading lockout events (4740) on the PDC.
```powershell
# Simple case
Find-LockoutSource jdoe
# More complex: which machines cause the most lockouts this week?
Find-LockoutSource -Hours 168 | Group-Object CallerComputer | Sort-Object Count -Descending
# More complex: query a specific DC and save the events
Find-LockoutSource jdoe@contoso.com -Server DC01.contoso.com | Export-Csv C:\Temp\lockouts.csv -NoTypeInformation
```
Gotcha: you need rights to read the Security log on the DC. Lockouts are logged on the PDC emulator, so querying another DC may show nothing.

### `Get-LapsPassword` (`laps`)
Copies a computer's LAPS admin password to the clipboard and clears it after 30 seconds.
```powershell
# Simple case
laps PC-0423
# More complex: keep it on the clipboard for two minutes, computer from the pipeline
Get-ADComputer 'PC-0423' | Get-LapsPassword -ClearAfter 120
# More complex: see which account and expiry it belongs to (password is never printed)
laps PC-0423 | Select-Object ComputerName, Account, ExpirationTimestamp
```
Gotcha: each call overwrites the clipboard, so don't pipe many computers at once. `-ClearAfter 0` leaves the password on the clipboard, and Windows clipboard history (Win+V) may still keep it.

### `Reset-LapsADPassword` (`lapsreset`)
Expires a computer's LAPS password so the device rotates it at its next policy check.
```powershell
# Simple case
lapsreset PC-0423
# More complex: preview a batch from a name pattern
Get-ADComputer -Filter "Name -like 'LAB-*'" | Reset-LapsADPassword -WhatIf
# More complex: expire, then fetch the new password later
lapsreset PC-0423
# ...after the device's next policy cycle:
laps PC-0423
```
Gotcha: the password is not changed immediately. The old one stays valid until the device processes policy (typically within an hour).

### `Start-ADSync`
Starts an Entra Connect delta sync on the sync server.
```powershell
# Simple case
Start-ADSync
# More complex: preview against a specific server
Start-ADSync -ComputerName 'sync01.contoso.com' -PolicyType Delta -WhatIf
# More complex: act on the result
$r = Start-ADSync
if (-not $r.Success) { Write-Warning $r.Message }
```
Gotcha: `-PolicyType Initial` runs a full sync and can take much longer. Success means the cycle was queued, not that it finished; check with `Get-ADSyncStatus`.

### `Get-ADSyncStatus`
Shows the Entra Connect scheduler state and the results of the most recent sync runs.
```powershell
# Simple case
Get-ADSyncStatus
# More complex: only failing runs out of the last 50
(Get-ADSyncStatus -Last 50).RecentRuns | Where-Object Result -ne 'success'
# More complex: is a cycle running, and when is the next one?
Get-ADSyncStatus -ComputerName 'sync01.contoso.com' | Select-Object SyncCycleInProgress, NextSyncCycleStart
```
Gotcha: the command always returns an object, even on failure. Check `.Success` and `.Message` before trusting the other fields.

### `Get-ConnectedDC` (`mydc`)
Shows which domain controller you're on: logon server, secure-channel DC, and the DC the locator returns (with IP and site).
```powershell
# Simple case
mydc
# More complex: compare the three views for another domain
mydc -Domain contoso.com | Select-Object LogonServer, SecureChannel, LocatorDC, LocatorSite
```
Gotcha: the three values can legitimately differ (logon server is who authenticated you earlier; the locator answers right now).

## Exchange / Microsoft 365

### `Connect-M365`
Signs in to Microsoft Graph and Exchange Online, skipping whichever is already connected.
```powershell
# Simple case: both services
Connect-M365

# More complex: Exchange only, browser sign-in instead of WAM (useful in a runas shell)
Connect-M365 -Exchange -DisableWAM

# More complex: Graph only with specific scopes, then disconnect both when done
Connect-M365 -Graph -Scopes 'User.Read.All','Group.Read.All'
Connect-M365 -Disconnect
```
Gotcha: the other Exchange / M365 commands call this for you, so you rarely need it by hand. Existing Graph sessions are reused only if they already hold every requested scope.

### `Show-InboxRuleDescription` (`ibr`, `gir`)
Lists a mailbox's inbox rules with plain-English descriptions.
```powershell
# Simple case
ibr jdoe@contoso.com

# More complex: which enabled rules exist, including hidden ones?
ibr jdoe@contoso.com -IncludeHidden | Where-Object Enabled

# More complex: several mailboxes into one CSV
'a@contoso.com', 'b@contoso.com' | ibr | Sort-Object Mailbox, Priority | Export-Csv .\rules.csv -NoTypeInformation
```
Gotcha: it takes one mailbox per pipeline item (string); piping Get-Mailbox output works too.

### `Get-ExternalForwarding` (`extfwd`)
Finds mailbox-level and inbox-rule forwards to addresses outside your accepted domains.
```powershell
# Simple case: whole tenant, saved to CSV
extfwd -Export

# More complex: fast check of two mailboxes, mailbox-level forwarding only, internal targets included
extfwd -Mailbox jdoe@contoso.com, asmith@contoso.com -SkipInboxRules -IncludeInternal

# More complex: disabled rules that still forward outside
extfwd | Where-Object { $_.Source -eq 'InboxRule' -and $_.RuleEnabled -eq $false } | Format-Table Mailbox, RuleName, Target
```
Gotcha: scanning inbox rules for every mailbox is slow on large tenants; use -SkipInboxRules for a quick first pass.

### `Get-GroupLicenseGap`
Lists members of a license group who do not hold the license that group should grant.
```powershell
# Simple case: use the groups from config and save the results
Get-GroupLicenseGap -Export

# More complex: one group, either of two SKUs counts, ignore disabled accounts
Get-GroupLicenseGap -GroupName 'LIC-M365-E3' -SkuPartNumber 'SPE_E3', 'ENTERPRISEPACK' -ExcludeDisabled

# More complex: which users failed group-based assignment (for example out of seats)?
Get-GroupLicenseGap -GroupName 'LIC-M365-E3' -SkuPartNumber 'SPE_E3' | Where-Object AssignmentError | Format-Table UserPrincipalName, AssignmentError

# More complex: which SKUs are nearly out of seats?
Get-GroupLicenseGap -ListSkus | Where-Object Free -lt 5
```
Gotcha: SKU names are part numbers (SPE_E3, ENTERPRISEPACK), not marketing names; run -ListSkus to see what your tenant uses. -ListSkus cannot be combined with the other parameters.

### `Get-LicenseReclaim`
Finds licensed users who are disabled, inactive, or never signed in, so their licenses can be freed.
```powershell
# Simple case: 90 days (or StaleDays from config)
Get-LicenseReclaim

# More complex: only E3 holders, 120-day threshold, disabled accounts only
Get-LicenseReclaim -SkuPartNumber 'SPE_E3', 'ENTERPRISEPACK' -Days 120 | Where-Object Reason -eq 'Disabled'

# More complex: the ten longest-inactive users
Get-LicenseReclaim | Where-Object Reason -eq 'Inactive' | Sort-Object DaysInactive -Descending | Select-Object -First 10

# More complex: full account details for each candidate before removing anything
Get-LicenseReclaim -Days 180 | Get-M365UserInfo | Format-List DisplayName, LastSignIn, Licenses, LicenseErrors
```
Gotcha: needs Entra ID P1 and the AuditLog.Read.All scope with admin consent, or Graph answers 403. Disabled accounts are reported regardless of -Days.

### `Get-M365UserInfo` (`m365info`)
Shows one user's Microsoft 365 account: licenses and their source, last sign-in, MFA methods, and optionally mailbox details.
```powershell
# Simple case
m365info jdoe@contoso.com

# More complex: a list of users, only those with mailbox forwarding set
Get-Content .\users.txt | m365info -Mailbox | Where-Object Forwarding | Select-Object UserPrincipalName, Forwarding

# More complex: see where each license comes from (direct or a group)
m365info jdoe@contoso.com | Select-Object -ExpandProperty Licenses

# More complex: reclaim candidates that also have license assignment errors
Get-LicenseReclaim -Days 90 | m365info | Where-Object LicenseErrors | Select-Object UserPrincipalName, LicenseErrors
```
Gotcha: input without an @ is treated as a SamAccountName and needs the ActiveDirectory module. Without AuditLog.Read.All or UserAuthenticationMethod.Read.All the sign-in or MFA fields read 'unavailable'.

## Network

### `Test-Port` (`tp`)
Checks whether specific TCP ports are open on one or more hosts, fast and in parallel.
```powershell
# Simple case
tp server01 443

# More complex: which of my web and database hosts are not answering on HTTPS or SQL?
'web01','web02','db01' | Test-Port -Port 443,1433 -TimeoutMs 3000 | Where-Object { -not $_.Open }
```
Gotcha: a name that does not resolve to an IPv4 address gives a warning and Open = False for every port, so a False can mean DNS, not a closed port.

### `Get-CertExpiry`
Shows when a TLS certificate expires and flags ones expiring soon.
```powershell
# Simple case
Get-CertExpiry github.com

# More complex: which of these endpoints need attention, soonest expiry first?
'web01.contoso.com','https://api.example.com','ldap01.contoso.com:636' | Get-CertExpiry -WarnDays 45 | Sort-Object DaysRemaining | Format-Table HostName, Port, DaysRemaining, Status
```
Gotcha: trust is not validated, so a self-signed or expired certificate is reported normally. Unreachable hosts come back with Status = Error.

### `Get-PublicIP`
Returns this machine's public (internet-facing) IP address.
```powershell
# Simple case
Get-PublicIP

# More complex: which lookup service answered?
Get-PublicIP -Verbose
```

### `Get-RemoteSystemInfo`
Shows OS, uptime, logged-on user, memory, and disk space for one or more computers.
```powershell
# Simple case
Get-RemoteSystemInfo srv01

# More complex: which servers could not be reached, and what are the others' disks like?
Get-Content servers.txt | Get-RemoteSystemInfo -ThrottleLimit 10 | Select-Object ComputerName, Uptime, DiskSummary, Error
```
Gotcha: remote targets need WinRM (PowerShell remoting) enabled. Unreachable hosts return an object with the Error property set instead of stopping the run.

## Utility

### `Show-WyattTools` (`tools`)
Lists all WyattTools commands and aliases.
```powershell
# Simple case
tools

# More complex: see the synopsis and first example for every command, wrapped narrow
Show-WyattTools -Detailed -Width 80
```

### `Get-FileTail` (`tail`)
Shows the last lines of a file; `-f` keeps following it.
```powershell
# Simple case
tail app.log

# More complex: watch a log live, starting from only new lines
tail app.log -Lines 0 -Follow

# More complex: last 200 lines, only the errors
tail -n 200 app.log | grep -i error
```
Gotcha: with -Follow the command runs until you press Ctrl+C, so it cannot be piped onward to something that waits for it to finish.

### `Invoke-ApiGet` (`get`)
Sends a GET request and returns the status code, timing, and parsed body.
```powershell
# Simple case
get https://api.example.com/users/5

# More complex: authenticated call, then use only the parsed body
$r = get https://api.example.com/users @{ Authorization = 'Bearer <token>' }
$r.StatusCode; $r.ElapsedMs; $r.Body | Select-Object -First 5
```
Gotcha: non-2xx responses are returned, not thrown, so check StatusCode instead of relying on try/catch.

### `Invoke-ApiPost` (`post`)
Sends a POST request with a JSON body and returns the status code, timing, and parsed body.
```powershell
# Simple case
post https://api.example.com/users '{"name":"Ada"}'

# More complex: build the JSON from a hashtable and send an API key header
$body = @{ name = 'Ada'; roles = @('admin','dev') } | ConvertTo-Json -Compress
post https://api.example.com/users $body @{ 'X-Api-Key' = '<key>' } | Select-Object StatusCode, ElapsedMs, RawBody
```
Gotcha: Body is a raw JSON string (convert objects with ConvertTo-Json first). Headers is the third positional parameter, after Body.

### `Convert-ToBase64` (`B64E`)
Base64-encodes a string (UTF-8).
```powershell
# Simple case
B64E 'hello'

# More complex: build the value for a Basic authentication header
$token = 'user:p@ssw0rd' | Convert-ToBase64
get https://api.example.com/me @{ Authorization = "Basic $token" }
```

### `grep`
Searches files or piped output for a regex pattern, grep-style.
```powershell
# Simple case
grep error app.log

# More complex: which scripts mention Connect-MgGraph, ignoring case, with line numbers?
grep -i -n -r 'connect-mg' ./Scripts

# More complex: how many errors in each log, and which lines are not comments?
grep -c -i error app.log web.log
grep -v '^#' settings.conf

# Piped objects are searched as the text you would see on screen
Get-Service | grep -i sql
```
Gotcha: flags are separate (-i -r -n, not -irn) and it is case-sensitive unless you pass -i. Folders need -r. For big trees use `rg`.

## Git

### `add`
Stages files (`git add`, defaults to everything).
```powershell
# Simple case
add

# More complex: stage one file only
add .\file.txt
```

### `commit`
Commits staged changes with a message (`git commit -m`).
```powershell
# Simple case
commit "Fix typo"

# More complex: stage and commit in one line
add; commit "Add examples to Network commands"
```

### `push`
Pushes a branch to origin (`git push origin <branch>`).
```powershell
# Simple case
push main

# More complex: stage, commit, and push in one line
add; commit "Update docs"; push main
```
Gotcha: the branch name is required; there is no default.

### `pull`
Pulls a branch from origin (`git pull origin <branch>`).
```powershell
# Simple case
pull main

# More complex: bring in the latest, then see what changed
pull main; git log --oneline -5
```
