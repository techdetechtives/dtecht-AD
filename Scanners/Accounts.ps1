#Requires -Version 5.1
<#
    Accounts (PingCastle equivalents: user/admin account hygiene rules)
    AD-only. Reviews every ENABLED user account and reports:

      Privileged accounts   - in Domain Admins / Administrators / other admin groups (direct or nested)
      Service accounts      - user accounts with an SPN or a name matching -ServiceAccountPattern, plus gMSAs
      Password never expires, password not required, reversible encryption, DES-only
      Never logged on, stale (no logon in -ActiveDays), old passwords (> -PasswordAgeDays)
      Kerberoastable (SPN on user), AS-REP roastable (no pre-auth)
      Unconstrained / constrained delegation (users and non-DC computers)
      Too many group memberships (> -MaxGroupMemberships), SID history, orphaned adminCount
      Privileged accounts not 'sensitive and cannot be delegated' / not in Protected Users
      Password-like text in the description field
      Cleartext password attributes (userPassword, unixUserPassword, msSFU30Password, os400Password)
      Unexpected primaryGroupID (hidden group membership) on users and computers

    Only accounts with at least one issue, plus all privileged and service accounts,
    are written out (so the CSV doubles as a privileged/service account inventory).
#>

function Invoke-ADAuditAccountScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Privileged,
        [string]$Server,
        [string]$SearchBase,
        [pscredential]$Credential,
        [int]$ActiveDays = 90,
        [int]$NeverLoggedOnGraceDays = 30,
        [int]$PasswordAgeDays = 365,
        [int]$MaxGroupMemberships = 20,
        [string]$ServiceAccountPattern = '^(svc|srv|sa|sql|app|service)[-_.]|[-_.](svc|service|sa)$|^svc'
    )

    $now = [DateTime]::UtcNow
    $props = 'sAMAccountName', 'displayName', 'distinguishedName', 'userAccountControl', 'lastLogonTimestamp', 'pwdLastSet',
             'whenCreated', 'servicePrincipalName', 'memberOf', 'adminCount', 'sIDHistory', 'description', 'msDS-AllowedToDelegateTo',
             'primaryGroupID', 'objectSid', 'userPassword', 'unixUserPassword', 'msSFU30Password', 'os400Password'
    $filter = '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $privilegedRids = 512, 516, 518, 519, 520, 521, 526, 527, 498
    # Adds to the $sev / $issues lists of the current loop iteration (dynamic scope)
    function Add-Issue([string]$s, [string]$t) { $sev.Add($s); $issues.Add($t) }

    foreach ($u in (Invoke-ADAuditLdapQuery -Server $Server -SearchBase $SearchBase -Credential $Credential -Filter $filter -Properties $props)) {
        $sam = [string]$u.sAMAccountName
        $dn = [string]$u.distinguishedName
        $uac = [int]$u.userAccountControl
        $spns = @($u.servicePrincipalName | Where-Object { $_ })
        $groups = @($u.memberOf | Where-Object { $_ })
        $lastLogon = ConvertFrom-ADAuditFileTime $u.lastLogonTimestamp
        $pwdSet = ConvertFrom-ADAuditFileTime $u.pwdLastSet
        $created = $null; if ($u.whenCreated) { $created = ([DateTime]$u.whenCreated).ToUniversalTime() }

        $isPriv = $Privileged.MapByMember.ContainsKey($dn)
        $privGroups = $(if ($isPriv) { ($Privileged.MapByMember[$dn] -join ', ') } else { $null })
        $isSvc = ($spns.Count -gt 0) -or ($sam -match $ServiceAccountPattern)
        $isProtected = $Privileged.ProtectedUsers.Contains($dn)
        $neverExpires = ($uac -band 0x10000) -ne 0
        $pwdAge = $(if ($pwdSet) { [int]($now - $pwdSet).TotalDays } else { $null })

        $issues = New-Object System.Collections.Generic.List[string]
        $sev = New-Object System.Collections.Generic.List[string]

        if ($uac -band 0x400000) { Add-Issue 'High' 'Kerberos pre-auth not required (AS-REP roastable)' }
        if ($uac -band 0x80) { Add-Issue 'High' 'Reversible password encryption enabled' }
        if ($uac -band 0x20) { Add-Issue $(if ($isPriv) { 'High' } else { 'Medium' }) 'Password not required (PASSWD_NOTREQD)' }
        if ($uac -band 0x200000) { Add-Issue 'Medium' 'DES-only Kerberos encryption' }
        if ($uac -band 0x80000) { Add-Issue 'High' 'Unconstrained delegation on user account' }
        if ($uac -band 0x1000000) { Add-Issue 'Medium' 'Constrained delegation with protocol transition' }
        elseif (@($u.'msDS-AllowedToDelegateTo' | Where-Object { $_ }).Count -gt 0) { Add-Issue 'Low' 'Constrained delegation configured' }
        if ($spns.Count -gt 0 -and $sam -ne 'krbtgt') {
            Add-Issue $(if ($isPriv) { 'High' } else { 'Medium' }) $(if ($isPriv) { 'Privileged account has SPN (Kerberoastable)' } else { 'User account has SPN (Kerberoastable) - consider gMSA' })
        }
        if ($neverExpires) {
            Add-Issue $(if ($isPriv) { 'High' } elseif ($isSvc) { 'Medium' } else { 'Low' }) 'Password never expires'
        }
        if (-not $lastLogon) {
            if ($created -and ($now - $created).TotalDays -gt $NeverLoggedOnGraceDays) {
                Add-Issue $(if ($isPriv) { 'Medium' } else { 'Low' }) 'Never logged on'
            }
        }
        elseif (($now - $lastLogon).TotalDays -gt $ActiveDays) {
            Add-Issue $(if ($isPriv) { 'Medium' } else { 'Low' }) ("No logon in {0} days (stale)" -f [int]($now - $lastLogon).TotalDays)
        }
        if ($null -ne $u.pwdLastSet -and [Int64]"$($u.pwdLastSet)" -eq 0) { Add-Issue 'Info' 'Must change password at next logon' }
        elseif ($pwdAge -and $pwdAge -gt $PasswordAgeDays) {
            Add-Issue $(if ($isPriv -or $isSvc) { 'Medium' } else { 'Low' }) "Password is $pwdAge days old"
        }
        if (@($u.sIDHistory | Where-Object { $_ }).Count -gt 0) { Add-Issue 'Medium' 'sIDHistory present' }
        if ($groups.Count -gt $MaxGroupMemberships) { Add-Issue 'Low' "Member of $($groups.Count) groups (limit $MaxGroupMemberships)" }
        if ($u.adminCount -eq 1 -and -not $isPriv) { Add-Issue 'Low' 'adminCount=1 but no longer privileged (orphaned AdminSDHolder ACL)' }
        if ($isPriv) {
            if (-not $isProtected) { Add-Issue 'Low' 'Privileged account not in Protected Users' }
            if ((($uac -band 0x100000) -eq 0) -and -not $isProtected) { Add-Issue 'Medium' "Privileged account not marked 'sensitive and cannot be delegated'" }
        }
        if ("$($u.description)" -match '(?i)\b(pass(word)?|pwd|p/w|kennwort|mot de passe)\b\s*[:=]?') { Add-Issue 'Medium' 'Description may contain a password' }
        foreach ($a in 'userPassword', 'unixUserPassword', 'msSFU30Password', 'os400Password') {
            if ($null -ne $u.$a -and "$($u.$a)" -ne '') { Add-Issue 'High' "Cleartext password stored in $a attribute" }
        }
        $pgid = $(if ($null -ne $u.primaryGroupID) { [int]$u.primaryGroupID } else { 513 })
        $rid = $(if ((ConvertTo-ADAuditSidString $u.objectSid) -match '-(\d+)$') { [int64]$Matches[1] } else { 0 })
        $expectedPg = $(if ($rid -eq 501) { 514 } else { 513 })   # Guest -> Domain Guests
        if ($pgid -ne $expectedPg -and $pgid -ne 513) {
            if ($pgid -in $privilegedRids) { Add-Issue 'High' "Primary group is privileged (RID $pgid) - hidden membership" }
            else { Add-Issue 'Low' "Unexpected primaryGroupID $pgid" }
        }

        if ($issues.Count -eq 0 -and -not $isPriv -and -not $isSvc) { continue }

        New-ADAuditResult -Scanner 'Accounts' -Target $sam -Severity (Get-ADAuditMaxSeverity @($sev)) -Finding ($issues -join '; ') -Data ([ordered]@{
            ObjectType           = 'user'
            DisplayName          = [string]$u.displayName
            IsPrivileged         = $isPriv
            PrivilegedGroups     = $privGroups
            IsServiceAccount     = $isSvc
            InProtectedUsers     = $isProtected
            PasswordNeverExpires = $neverExpires
            LastLogonUtc         = $lastLogon
            PasswordLastSetUtc   = $pwdSet
            PasswordAgeDays      = $pwdAge
            WhenCreatedUtc       = $created
            GroupCount           = $groups.Count
            SPNs                 = ($spns -join '; ')
            Description          = [string]$u.description
            PrimaryGroupId       = $pgid
            DistinguishedName    = $dn
            IssueSeverity        = (@($sev) -join ';')
        })
    }

    # Computers whose primaryGroupID doesn't match their type (515 member, 516 DC, 521 RODC)
    $pf = '(&(objectCategory=computer)(!(primaryGroupID=515))(!(primaryGroupID=516))(!(primaryGroupID=521)))'
    $cf = '(&(objectCategory=computer)(|(&(primaryGroupID=516)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))(&(primaryGroupID=521)(!(userAccountControl:1.2.840.113556.1.4.803:=67108864)))))'
    foreach ($q in @($pf, $cf)) {
        foreach ($c in (Invoke-ADAuditLdapQuery -Server $Server -SearchBase $SearchBase -Credential $Credential -Filter $q -Properties 'sAMAccountName', 'distinguishedName', 'primaryGroupID')) {
            $pg = [int]$c.primaryGroupID
            $sev1 = $(if ($pg -in $privilegedRids) { 'High' } else { 'Low' })
            $txt = $(if ($pg -in 516, 521) { "Non-DC computer has DC primaryGroupID $pg" } elseif ($sev1 -eq 'High') { "Primary group is privileged (RID $pg) - hidden membership" } else { "Unexpected primaryGroupID $pg" })
            New-ADAuditResult -Scanner 'Accounts' -Target ([string]$c.sAMAccountName) -Severity $sev1 -Finding $txt -Data ([ordered]@{
                ObjectType = 'computer'; PrimaryGroupId = $pg; DistinguishedName = [string]$c.distinguishedName
            })
        }
    }

    # Non-DC computers with unconstrained delegation (DC = 0x2000, RODC = 0x4000000)
    $cf = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67108864))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    foreach ($c in (Invoke-ADAuditLdapQuery -Server $Server -SearchBase $SearchBase -Credential $Credential -Filter $cf -Properties 'sAMAccountName', 'distinguishedName')) {
        New-ADAuditResult -Scanner 'Accounts' -Target ([string]$c.sAMAccountName) -Severity 'High' -Finding 'Non-DC computer trusted for unconstrained delegation' -Data ([ordered]@{
            ObjectType = 'computer'; DistinguishedName = [string]$c.distinguishedName
        })
    }

    # Group Managed Service Accounts (inventory - the good kind of service account)
    try {
        foreach ($g in (Invoke-ADAuditLdapQuery -Server $Server -SearchBase $SearchBase -Credential $Credential -Filter '(objectClass=msDS-GroupManagedServiceAccount)' -Properties 'sAMAccountName', 'distinguishedName', 'servicePrincipalName')) {
            New-ADAuditResult -Scanner 'Accounts' -Target ([string]$g.sAMAccountName) -Severity 'OK' -Finding 'gMSA' -Data ([ordered]@{
                ObjectType = 'gMSA'; IsServiceAccount = $true; IsPrivileged = $Privileged.MapByMember.ContainsKey([string]$g.distinguishedName)
                SPNs = (@($g.servicePrincipalName | Where-Object { $_ }) -join '; '); DistinguishedName = [string]$g.distinguishedName
            })
        }
    }
    catch { }
}
