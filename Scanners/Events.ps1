#Requires -Version 5.1
<#
    Events
    Reads (never clears or changes) the Security log on each DC for the last
    -EventDays days and reports account, group and directory changes.

      4720/4722/4725/4726/4738/4740/4767/4781  user created/enabled/disabled/deleted/changed/locked/unlocked/renamed
      4724                                     password reset by someone else
      4741                                     computer account created
      4728/4732/4756, 4729/4733/4757           member added to / removed from a security group
      4765/4766                                SID history added / add failed
      4794                                     DSRM administrator password set
      5136 (selected attributes)               SPN, delegation, RBCD, shadow credentials, sIDHistory,
                                               ACL on AdminSDHolder / domain root, gPLink, scriptPath

    Fields are read from the event XML by name, so it works on any DC language.
    4738 is only reported when a security-relevant field changed (UAC flags,
    delegation, SID history, primary group, logon script).

    Needs: membership of 'Event Log Readers' on DCs (or Domain Admins), remote
    event log access (RPC, TCP 135 + dynamic), and the matching audit subcategories
    enabled (see the AuditPolicy scanner). 5136 also needs SACLs on the objects.
#>

# SAM account-control bits as used by 4720/4738 (OldUacValue / NewUacValue)
$script:ADAuditSamUacBits = @(
    'Account Disabled', 'Home Directory Required', 'Password Not Required', 'Temp Duplicate Account', 'Normal Account',
    'MNS Logon Account', 'Interdomain Trust Account', 'Workstation Trust Account', 'Server Trust Account', "Don't Expire Password",
    'Account Locked', 'Encrypted Text Password Allowed', 'Smartcard Required', 'Trusted For Delegation', 'Not Delegated',
    'Use DES Key Only', "Don't Require Preauth", 'Password Expired', 'Trusted To Authenticate For Delegation', 'No Auth Data Required'
)
$script:ADAuditUacEnableSeverity = @{
    'Trusted For Delegation' = 'High'; "Don't Require Preauth" = 'High'; 'Password Not Required' = 'Medium'
    'Use DES Key Only' = 'Medium'; 'Trusted To Authenticate For Delegation' = 'Medium'; "Don't Expire Password" = 'Low'
    'Encrypted Text Password Allowed' = 'High'
}
$script:ADAuditUacDisableSeverity = @{ 'Smartcard Required' = 'Low'; 'Not Delegated' = 'Medium' }

$script:ADAuditEventNames = @{
    4720 = 'User account created'; 4722 = 'User account enabled'; 4724 = 'Password reset'; 4725 = 'User account disabled'
    4726 = 'User account deleted'; 4738 = 'User account changed'; 4740 = 'Account locked out'; 4741 = 'Computer account created'
    4767 = 'Account unlocked'; 4781 = 'Account renamed'; 4728 = 'Added to global group'; 4729 = 'Removed from global group'
    4732 = 'Added to local group'; 4733 = 'Removed from local group'; 4756 = 'Added to universal group'; 4757 = 'Removed from universal group'
    4765 = 'SID history added'; 4766 = 'SID history add failed'; 4794 = 'DSRM password set'; 5136 = 'Directory object modified'
}

$script:ADAudit5136Attributes = @(
    'servicePrincipalName', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
    'msDS-KeyCredentialLink', 'sIDHistory', 'nTSecurityDescriptor', 'gPLink', 'scriptPath', 'userAccountControl'
)

function Get-ADAuditEventQueryXml {
    param([int]$Days)
    $ms = [int64]$Days * 86400000
    $ids = (@(4720, 4722, 4724, 4725, 4726, 4738, 4740, 4741, 4767, 4781, 4728, 4729, 4732, 4733, 4756, 4757, 4765, 4766, 4794) | ForEach-Object { "EventID=$_" }) -join ' or '
    $attrs = ($script:ADAudit5136Attributes | ForEach-Object { "Data[@Name='AttributeLDAPDisplayName']='$_'" }) -join ' or '
    return @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[($ids) and TimeCreated[timediff(@SystemTime) &lt;= $ms]]]</Select>
    <Select Path="Security">*[System[EventID=5136 and TimeCreated[timediff(@SystemTime) &lt;= $ms]]] and *[EventData[$attrs]]</Select>
  </Query>
</QueryList>
"@
}

function ConvertFrom-ADAuditEventXml {
    param([Parameter(Mandatory)][string]$Xml)
    $x = [xml]$Xml
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[[string]$n.Name] = [string]$n.'#text' } }
    return $d
}

function Get-ADAuditUacChange {
    param([string]$Old, [string]$New)
    try { $o = [Convert]::ToInt64(($Old -replace '^0x', ''), 16); $n = [Convert]::ToInt64(($New -replace '^0x', ''), 16) } catch { return $null }
    $on = @(); $off = @()
    for ($i = 0; $i -lt $script:ADAuditSamUacBits.Count; $i++) {
        $bit = [int64]1 -shl $i
        if ((($n -band $bit) -ne 0) -and (($o -band $bit) -eq 0)) { $on += $script:ADAuditSamUacBits[$i] }
        if ((($o -band $bit) -ne 0) -and (($n -band $bit) -eq 0)) { $off += $script:ADAuditSamUacBits[$i] }
    }
    [pscustomobject]@{ Enabled = $on; Disabled = $off }
}

function Get-ADAuditUsefulValue {
    param([string]$Value)
    if (-not $Value -or $Value -eq '-' -or $Value -match '^%%1793$') { return $null }   # %%1793 = <value not set>
    return $Value
}

function ConvertTo-ADAuditEventResult {
    <#
        Turns one event (id, time, dc, data hashtable) into a result row, or $null
        when the event is not interesting (e.g. a 4738 with no security-relevant change).
    #>
    param(
        [Parameter(Mandatory)][int]$Id,
        [Parameter(Mandatory)][datetime]$TimeCreated,
        [Parameter(Mandatory)][string]$DC,
        [Parameter(Mandatory)][hashtable]$D,
        [hashtable]$PrivilegedSids = @{},
        [hashtable]$PrivilegedNames = @{},
        [string]$DomainDN
    )

    $actor = $(if ($D['SubjectUserName'] -and $D['SubjectUserName'] -ne '-') { "$($D['SubjectDomainName'])\$($D['SubjectUserName'])" } else { $null })
    $target = $(if ($D['TargetUserName']) { "$($D['TargetDomainName'])\$($D['TargetUserName'])".TrimStart('\') } else { $null })
    $action = $script:ADAuditEventNames[$Id]
    $sev = 'Info'; $detail = ''; $group = $null; $member = $null

    $isPrivTarget = ($D['TargetSid'] -and $PrivilegedSids.ContainsKey($D['TargetSid'])) -or ($D['TargetUserName'] -and $PrivilegedNames.ContainsKey($D['TargetUserName']))

    switch ($Id) {
        { $_ -in 4728, 4732, 4756 } {
            $group = $target; $member = $(if ($D['MemberName'] -and $D['MemberName'] -ne '-') { $D['MemberName'] } else { $D['MemberSid'] })
            $target = $member
            if ($D['TargetSid'] -and $PrivilegedSids.ContainsKey($D['TargetSid'])) { $sev = 'High'; $detail = "Added to privileged group $group" }
            else { $detail = "Added to $group" }
        }
        { $_ -in 4729, 4733, 4757 } {
            $group = $target; $member = $(if ($D['MemberName'] -and $D['MemberName'] -ne '-') { $D['MemberName'] } else { $D['MemberSid'] })
            $target = $member
            if ($D['TargetSid'] -and $PrivilegedSids.ContainsKey($D['TargetSid'])) { $sev = 'Medium'; $detail = "Removed from privileged group $group" }
            else { $detail = "Removed from $group" }
        }
        4720 { $detail = 'New user account' }
        4741 { $detail = "New computer account (created by $actor)" }
        4726 { $sev = 'Low'; $detail = 'User account deleted' }
        4724 { if ($isPrivTarget) { $sev = 'Medium'; $detail = 'Password of a privileged account reset by another account' } else { $detail = 'Password reset by another account' } }
        4740 { $detail = "Locked out (caller computer: $($D['TargetDomainName']))"; $target = $D['TargetUserName'] }
        4781 { $sev = 'Low'; $target = $D['NewTargetUserName']; $detail = "Renamed from $($D['OldTargetUserName']) to $($D['NewTargetUserName'])" }
        4765 { $sev = 'High'; $detail = "SID history added (source: $($D['SourceUserName']), SIDs: $($D['SidList']))" }
        4766 { $sev = 'Medium'; $detail = "SID history add failed (source: $($D['SourceUserName']))" }
        4794 { $sev = 'High'; $target = $DC; $detail = "DSRM administrator password set from $($D['Workstation']) (status $($D['Status']))" }
        4738 {
            $parts = @(); $sevs = @()
            $uac = Get-ADAuditUacChange -Old $D['OldUacValue'] -New $D['NewUacValue']
            if ($uac) {
                foreach ($f in $uac.Enabled) {
                    if ($script:ADAuditUacEnableSeverity.ContainsKey($f)) { $parts += "$f enabled"; $sevs += $script:ADAuditUacEnableSeverity[$f] }
                }
                foreach ($f in $uac.Disabled) {
                    if ($script:ADAuditUacDisableSeverity.ContainsKey($f)) { $parts += "$f disabled"; $sevs += $script:ADAuditUacDisableSeverity[$f] }
                }
            }
            if (Get-ADAuditUsefulValue $D['AllowedToDelegateTo']) { $parts += "Delegation set to $($D['AllowedToDelegateTo'])"; $sevs += 'Medium' }
            if (Get-ADAuditUsefulValue $D['SidHistory']) { $parts += 'SID history changed'; $sevs += 'High' }
            if (Get-ADAuditUsefulValue $D['PrimaryGroupId']) { $parts += "Primary group changed to RID $($D['PrimaryGroupId'])"; $sevs += 'Medium' }
            if (Get-ADAuditUsefulValue $D['ScriptPath']) { $parts += "Logon script set to $($D['ScriptPath'])"; $sevs += 'Low' }
            if ($parts.Count -eq 0) { return $null }
            if ($isPrivTarget) { $sevs += 'Medium' }
            $sev = Get-ADAuditMaxSeverity $sevs
            $detail = $parts -join '; '
        }
        5136 {
            $attr = $D['AttributeLDAPDisplayName']
            $op = switch ($D['OperationType']) { '%%14674' { 'added' } '%%14675' { 'removed' } default { 'changed' } }
            $obj = $D['ObjectDN']; $class = $D['ObjectClass']
            $target = $obj
            $val = [string]$D['AttributeValue']
            if ($val.Length -gt 200) { $val = $val.Substring(0, 200) + '...' }
            $isRoot = $DomainDN -and ($obj -ieq $DomainDN)
            $isAdminSd = $obj -match '^CN=AdminSDHolder,CN=System,'
            switch ($attr) {
                'msDS-KeyCredentialLink' { $sev = $(if ($op -eq 'added' -and $class -ne 'computer') { 'High' } elseif ($op -eq 'added') { 'Medium' } else { 'Info' }); $detail = "Key credential $op (shadow credentials if unexpected)" }
                'msDS-AllowedToActOnBehalfOfOtherIdentity' { $sev = $(if ($op -eq 'added') { 'High' } else { 'Info' }); $detail = "Resource-based constrained delegation $op" }
                'msDS-AllowedToDelegateTo' { $sev = $(if ($op -eq 'added') { 'Medium' } else { 'Info' }); $detail = "Constrained delegation target $op`: $val" }
                'servicePrincipalName' { $sev = $(if ($op -eq 'added' -and $class -eq 'user') { 'Medium' } else { 'Info' }); $detail = "SPN $op on $class`: $val" }
                'sIDHistory' { $sev = $(if ($op -eq 'added') { 'High' } else { 'Info' }); $detail = "sIDHistory $op" }
                'nTSecurityDescriptor' {
                    if ($op -eq 'removed') { return $null }   # every ACL change logs remove-old + add-new; keep the add
                    $sev = $(if ($isAdminSd -or $isRoot) { 'High' } else { 'Low' })
                    $detail = $(if ($isAdminSd) { 'ACL changed on AdminSDHolder (persists to all protected accounts)' } elseif ($isRoot) { 'ACL changed on domain root (DCSync rights?)' } else { "ACL changed on $class" })
                }
                'gPLink' { if ($op -eq 'removed') { return $null }; $sev = 'Low'; $detail = "GPO links changed on $class" }
                'scriptPath' { if ($op -eq 'removed') { return $null }; $sev = 'Low'; $detail = "Logon script set: $val" }
                'userAccountControl' {
                    if ($op -ne 'added' -or $class -ne 'computer') { return $null }   # users are covered by 4738
                    $v = 0; [void][int]::TryParse($D['AttributeValue'], [ref]$v)
                    if ($v -band 0x80000) { $sev = 'High'; $detail = 'Computer trusted for unconstrained delegation' }
                    elseif ($v -band 0x1000000) { $sev = 'Medium'; $detail = 'Computer trusted to authenticate for delegation' }
                    else { return $null }
                }
            }
            $action = "Attribute $attr $op"
        }
    }

    New-ADAuditResult -Scanner 'Events' -Target $(if ($target) { $target } else { '(unknown)' }) -Severity $sev -Finding $detail -Data ([ordered]@{
        Check       = 'Event'
        TimeCreated = $TimeCreated
        DC          = $DC
        EventId     = $Id
        Action      = $action
        Actor       = $actor
        Group       = $group
    })
}

function Invoke-ADAuditEventScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [int]$EventDays = 7,
        [int]$MaxEvents = 5000,
        [hashtable]$PrivilegedSids = @{},
        [hashtable]$PrivilegedNames = @{},
        [string]$DomainDN,
        [int]$TimeoutMs = 3000
    )

    if (-not (Test-ADAuditTcpPort -ComputerName $ComputerName -Port 135 -TimeoutMs $TimeoutMs)) {
        New-ADAuditResult -Scanner 'Events' -Target $ComputerName -Severity 'Info' -Finding 'TCP 135 (RPC) not reachable; Security log not read' -Data ([ordered]@{ Check = 'Coverage'; DC = $ComputerName })
        return
    }

    # How far back does the Security log actually go?
    $oldest = $null
    try {
        $o = Get-WinEvent -ComputerName $ComputerName -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
        $oldest = $o.TimeCreated
    }
    catch [System.UnauthorizedAccessException] {
        New-ADAuditResult -Scanner 'Events' -Target $ComputerName -Severity 'Error' -Finding "Access denied reading Security log - add the scanning account to 'Event Log Readers' on DCs" -Data ([ordered]@{ Check = 'Coverage'; DC = $ComputerName })
        return
    }
    catch {
        New-ADAuditResult -Scanner 'Events' -Target $ComputerName -Severity 'Error' -Finding "Could not read Security log: $($_.Exception.Message)" -Data ([ordered]@{ Check = 'Coverage'; DC = $ComputerName })
        return
    }

    $events = @()
    $truncated = $false
    try {
        $events = @(Get-WinEvent -ComputerName $ComputerName -FilterXml ([xml](Get-ADAuditEventQueryXml -Days $EventDays)) -MaxEvents $MaxEvents -ErrorAction Stop)
        $truncated = $events.Count -ge $MaxEvents
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            New-ADAuditResult -Scanner 'Events' -Target $ComputerName -Severity 'Error' -Finding "Event query failed: $($_.Exception.Message)" -Data ([ordered]@{ Check = 'Coverage'; DC = $ComputerName })
            return
        }
    }

    $reported = 0
    foreach ($e in $events) {
        try {
            $r = ConvertTo-ADAuditEventResult -Id $e.Id -TimeCreated $e.TimeCreated -DC $ComputerName -D (ConvertFrom-ADAuditEventXml $e.ToXml()) -PrivilegedSids $PrivilegedSids -PrivilegedNames $PrivilegedNames -DomainDN $DomainDN
            if ($r) { $reported++; $r }
        }
        catch { New-ADAuditResult -Scanner 'Events' -Target $ComputerName -Severity 'Error' -Finding "Could not parse event $($e.Id) record $($e.RecordId): $($_.Exception.Message)" -Data ([ordered]@{ Check = 'Event'; DC = $ComputerName }) }
    }

    $windowStart = (Get-Date).AddDays(-$EventDays)
    $sev = 'OK'; $notes = @()
    if ($oldest -and $oldest -gt $windowStart) {
        $hours = [int]((Get-Date) - $oldest).TotalHours
        $sev = $(if ($hours -lt 24) { 'Medium' } else { 'Low' })
        $notes += "Security log only covers the last $hours hours (oldest event $($oldest.ToString('yyyy-MM-dd HH:mm'))) - increase its size or forward to SIEM"
    }
    if ($truncated) { $notes += "Hit -MaxEvents $MaxEvents; older matching events not reviewed"; $sev = Get-ADAuditMaxSeverity @($sev, 'Info') }
    $notes = @("$($events.Count) matching events, $reported reported") + $notes

    New-ADAuditResult -Scanner 'Events' -Target $ComputerName -Severity $sev -Finding ($notes -join '; ') -Data ([ordered]@{
        Check = 'Coverage'; DC = $ComputerName; OldestEvent = $oldest; WindowDays = $EventDays
    })
}
