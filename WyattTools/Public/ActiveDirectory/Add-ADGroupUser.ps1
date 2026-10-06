<#
.SYNOPSIS
    Adds users to an AD group from a file, a single user, or the pipeline.
.DESCRIPTION
    Resolves each identifier (email, UPN, or SamAccountName) to an AD user and adds the user to
    the group. Only DIRECT membership is considered: users who are already direct members are
    skipped. Direct member DNs are fetched once up front. A transcript is written to %TEMP% and is
    always stopped, even if the run fails. Pipeline input is collected first and processed once
    the pipeline completes.
.PARAMETER File
    Path to a text/CSV file with one identifier per line (header row and blank lines are skipped).
.PARAMETER User
    One or more identifiers (email, UPN, or SamAccountName). Accepts pipeline input.
.PARAMETER Group
    Name or DistinguishedName of the AD group.
.EXAMPLE
    Add-ADGroupUser -File "C:\users.csv" -Group "Sales Team"
.EXAMPLE
    Add-ADGroupUser -User "jdoe@contoso.com" -Group "Sales Team" -WhatIf
.EXAMPLE
    Get-Content .\users.txt | Add-ADGroupUser -Group "Sales Team"
.EXAMPLE
    Add-ADGroupUser -File "C:\Temp\users.csv" -Group "VPN-Users" -WhatIf -Verbose
    Previews a CSV load; -Verbose also lists the users skipped because they are already direct members.
.EXAMPLE
    Add-ADGroupUser -User 'jdoe','asmith@contoso.com' -Group "VPN-Users"
    Adds several users in one call; each identifier can be a SamAccountName, UPN, or email.
.EXAMPLE
    Import-Csv C:\Temp\users.csv | Select-Object -ExpandProperty Email | Add-ADGroupUser -Group "VPN-Users"
    Pulls one column out of a multi-column CSV and pipes the identifiers in.
.NOTES
    Name: Add-ADGroupUser
    Version: 2.1.0
    Author: WGuethlein
    Date: 2026-10-04
    Prerequisites: ActiveDirectory module, rights to modify the group
#>
function Add-ADGroupUser {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$File,

        [Parameter(Mandatory, ParameterSetName = 'SingleUser', ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string[]]$User,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Group
    )

    begin {
        Assert-Module -Name ActiveDirectory
        $pipelineUsers = New-Object 'System.Collections.Generic.List[string]'
    }

    # Only collect input here; all work happens in end{} so one try/finally can guarantee
    # Stop-Transcript runs even after a terminating error.
    process {
        if ($PSCmdlet.ParameterSetName -eq 'SingleUser') {
            foreach ($u in $User) { $pipelineUsers.Add($u) }
        }
    }

    end {
        try {
            $adGroup = Get-ADGroup -Identity $Group -Properties Members -ErrorAction Stop
            Write-Verbose "Target group: $($adGroup.Name) ($($adGroup.DistinguishedName))"
        }
        catch {
            throw "AD group '$Group' not found: $_"
        }

        # Direct members only, fetched once (case-insensitive DN set).
        $memberDns = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($dn in $adGroup.Members) { [void]$memberDns.Add($dn) }

        $transcriptPath = Join-Path $env:TEMP "Add-ADGroupUser_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Start-Transcript -Path $transcriptPath -WhatIf:$false | Out-Null

        try {
            $successCount = 0
            $failCount = 0
            $notFoundCount = 0
            $alreadyMemberCount = 0
            Write-Host "Adding to group: $($adGroup.Name)" -ForegroundColor Cyan

            if ($PSCmdlet.ParameterSetName -eq 'File') {
                $resolved = @(Resolve-ADUserIdentity -File $File)
                Write-Host "Processing $($resolved.Count) users from '$File'" -ForegroundColor Cyan
            }
            else {
                $resolved = @(Resolve-ADUserIdentity -User $pipelineUsers.ToArray())
            }

            foreach ($item in $resolved) {
                if ($null -eq $item.ADUser) {
                    Write-Warning "User not found: $($item.Input) ($($item.Error))"
                    $notFoundCount++
                    continue
                }
                $adUser = $item.ADUser

                if ($memberDns.Contains($adUser.DistinguishedName)) {
                    Write-Verbose "Already a direct member (skipping): $($item.Input) ($($adUser.SamAccountName))"
                    $alreadyMemberCount++
                    continue
                }

                if ($PSCmdlet.ShouldProcess("$($item.Input) ($($adUser.SamAccountName))", "Add to $($adGroup.Name)")) {
                    try {
                        Add-ADGroupMember -Identity $adGroup -Members $adUser -ErrorAction Stop
                        [void]$memberDns.Add($adUser.DistinguishedName)
                        Write-Host "Added: $($item.Input) ($($adUser.SamAccountName))" -ForegroundColor Green
                        $successCount++
                    }
                    catch {
                        Write-Error "Failed to add $($item.Input): $_"
                        $failCount++
                    }
                }
            }

            Write-Host ""
            Write-Host "========== Summary ==========" -ForegroundColor Cyan
            Write-Host "Successfully added: $successCount" -ForegroundColor Green
            Write-Host "Failed: $failCount" -ForegroundColor Red
            Write-Host "Not found in AD: $notFoundCount" -ForegroundColor Yellow
            Write-Host "Already members: $alreadyMemberCount" -ForegroundColor Gray
            Write-Host "Transcript: $transcriptPath" -ForegroundColor Cyan
        }
        finally {
            $WhatIfPreference = $false  # Stop-Transcript has no -WhatIf in 5.1; must really stop
            Stop-Transcript | Out-Null
        }
    }
}
