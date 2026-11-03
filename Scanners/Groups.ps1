#Requires -Version 5.1
<#
    Groups (PingCastle equivalents: privileged group checks, nested group findings)
    AD-only. Reads group objects and uses LDAP_MATCHING_RULE_IN_CHAIN to resolve
    direct AND nested members of privileged groups.

    Reports:
      - Every member of each privileged group (direct or nested)
      - Computers / foreign principals / disabled accounts inside privileged groups
      - Operator groups and Schema/Enterprise Admins that are not empty
      - Groups nested deeper than -MaxNestingDepth, and circular nesting
#>

function Get-ADAuditGroupInventory {
    param([string]$Server, [string]$SearchBase, [pscredential]$Credential)
    $props = 'distinguishedName', 'sAMAccountName', 'objectSid', 'memberOf', 'adminCount', 'groupType'
    foreach ($g in (Invoke-ADAuditLdapQuery -Server $Server -SearchBase $SearchBase -Credential $Credential -Filter '(objectCategory=group)' -Properties $props)) {
        [pscustomobject]@{
            DistinguishedName = [string]$g.distinguishedName
            SamAccountName    = [string]$g.sAMAccountName
            Sid               = ConvertTo-ADAuditSidString $g.objectSid
            MemberOf          = @($g.memberOf | Where-Object { $_ } | ForEach-Object { [string]$_ })
            AdminCount        = $g.adminCount
        }
    }
}

function Get-ADAuditPrivilegedMembership {
    <#
        Returns:
          Groups         - privileged group objects found in this domain (with .Label)
          Members        - one row per (group, member), Direct = $true/$false
          MapByMember    - DN -> list of privileged group labels
          ProtectedUsers - HashSet of DNs in Protected Users (incl. nested)
    #>
    param([Parameter(Mandatory)][object[]]$Groups, [string]$Server, [string]$SearchBase, [pscredential]$Credential)

    $builtin = @{ 'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-548' = 'Account Operators'; 'S-1-5-32-549' = 'Server Operators'; 'S-1-5-32-550' = 'Print Operators'; 'S-1-5-32-551' = 'Backup Operators' }
    $domainRids = @{ '512' = 'Domain Admins'; '518' = 'Schema Admins'; '519' = 'Enterprise Admins'; '520' = 'Group Policy Creator Owners'; '526' = 'Key Admins'; '527' = 'Enterprise Key Admins' }

    $privGroups = @()
    $protectedGroup = $null
    foreach ($g in $Groups) {
        $label = $null
        if ($g.Sid -and $builtin.ContainsKey($g.Sid)) { $label = $builtin[$g.Sid] }
        elseif ($g.Sid -match '^S-1-5-21-.+-(\d+)$') {
            $rid = $Matches[1]
            if ($domainRids.ContainsKey($rid)) { $label = $domainRids[$rid] }
            elseif ($rid -eq '525') { $protectedGroup = $g }
        }
        if (-not $label -and $g.SamAccountName -eq 'DnsAdmins') { $label = 'DnsAdmins' }
        if ($label) { $privGroups += ($g | Select-Object *, @{ n = 'Label'; e = { $label } }) }
    }

    $memberProps = 'distinguishedName', 'sAMAccountName', 'objectClass', 'memberOf', 'userAccountControl'
    $rows = New-Object System.Collections.ArrayList
    $map = @{}
    foreach ($pg in $privGroups) {
        $f = '(memberOf:1.2.840.113556.1.4.1941:={0})' -f (ConvertTo-ADAuditLdapFilterValue $pg.DistinguishedName)
        foreach ($m in (Invoke-ADAuditLdapQuery -Server $Server -SearchBase $SearchBase -Credential $Credential -Filter $f -Properties $memberProps)) {
            $dn = [string]$m.distinguishedName
            $classes = @($m.objectClass)
            $class = [string]$classes[-1]
            $direct = @($m.memberOf | Where-Object { $_ -and ([string]$_ -ieq $pg.DistinguishedName) }).Count -gt 0
            $uac = 0; if ($null -ne $m.userAccountControl) { $uac = [int]$m.userAccountControl }
            [void]$rows.Add([pscustomobject]@{
                GroupLabel = $pg.Label
                GroupDN    = $pg.DistinguishedName
                MemberDN   = $dn
                MemberName = $(if ($m.sAMAccountName) { [string]$m.sAMAccountName } else { ($dn -split ',')[0] -replace '^CN=', '' })
                MemberType = $class
                Direct     = $direct
                Disabled   = (($uac -band 0x2) -ne 0)
                UAC        = $uac
            })
            if (-not $map.ContainsKey($dn)) { $map[$dn] = New-Object System.Collections.Generic.List[string] }
            if (-not $map[$dn].Contains($pg.Label)) { $map[$dn].Add($pg.Label) }
        }
    }

    $protected = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($protectedGroup) {
        $f = '(memberOf:1.2.840.113556.1.4.1941:={0})' -f (ConvertTo-ADAuditLdapFilterValue $protectedGroup.DistinguishedName)
        foreach ($m in (Invoke-ADAuditLdapQuery -Server $Server -SearchBase $SearchBase -Credential $Credential -Filter $f -Properties 'distinguishedName')) {
            [void]$protected.Add([string]$m.distinguishedName)
        }
    }

    [pscustomobject]@{ Groups = $privGroups; Members = @($rows); MapByMember = $map; ProtectedUsers = $protected }
}

function Get-ADAuditGroupDepth {
    # $Visiting is the current DFS path (List[string]); every group on a loop is added to $Cycles
    param($Dn, $Parents, $Memo, $Visiting, $Cycles)
    if ($Memo.ContainsKey($Dn)) { return $Memo[$Dn] }
    $idx = -1
    for ($i = 0; $i -lt $Visiting.Count; $i++) { if ($Visiting[$i] -ieq $Dn) { $idx = $i; break } }
    if ($idx -ge 0) {
        for ($i = $idx; $i -lt $Visiting.Count; $i++) { [void]$Cycles.Add($Visiting[$i]) }
        return 0
    }
    $Visiting.Add($Dn)
    $max = 0
    foreach ($p in $Parents[$Dn]) {
        if ($p -and $Parents.ContainsKey($p)) {
            $d = 1 + (Get-ADAuditGroupDepth -Dn $p -Parents $Parents -Memo $Memo -Visiting $Visiting -Cycles $Cycles)
            if ($d -gt $max) { $max = $d }
        }
    }
    $Visiting.RemoveAt($Visiting.Count - 1)
    $Memo[$Dn] = $max
    return $max
}

function Invoke-ADAuditGroupScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Groups,
        [Parameter(Mandatory)]$Privileged,
        [int]$MaxNestingDepth = 3
    )

    $shouldBeEmpty = @('Account Operators', 'Server Operators', 'Print Operators', 'Schema Admins', 'Enterprise Admins')

    # ---- Privileged groups: summary + members ----
    foreach ($pg in $Privileged.Groups) {
        $members = @($Privileged.Members | Where-Object { $_.GroupDN -eq $pg.DistinguishedName })
        $users = @($members | Where-Object { $_.MemberType -in 'user', 'inetOrgPerson' })
        $sev = 'Info'
        $finding = '{0} members ({1} direct, {2} users)' -f $members.Count, @($members | Where-Object { $_.Direct }).Count, $users.Count
        if ($members.Count -gt 0 -and $shouldBeEmpty -contains $pg.Label) {
            $sev = $(if ($pg.Label -like '*Operators') { 'Medium' } else { 'Low' })
            $finding += ' - this group should normally be empty'
        }
        New-ADAuditResult -Scanner 'Groups' -Target $pg.Label -Severity $sev -Finding $finding -Data ([ordered]@{
            Check = 'PrivilegedGroup'; Group = $pg.Label; Member = $null; MemberType = $null; Membership = $null; Disabled = $null; NestingDepth = $null; DistinguishedName = $pg.DistinguishedName
        })

        foreach ($m in $members) {
            $sev = 'Info'; $finding = 'Privileged group member'
            switch ($m.MemberType) {
                'computer' {
                    if (($m.UAC -band 0x2000) -eq 0) { $sev = 'High'; $finding = 'Computer account in privileged group' }
                }
                'foreignSecurityPrincipal' { $sev = 'Medium'; $finding = 'Foreign (cross-trust) principal in privileged group' }
                'group' { $finding = 'Group nested inside privileged group' }
                'msDS-GroupManagedServiceAccount' { $sev = 'Low'; $finding = 'gMSA in privileged group - confirm it needs this' }
            }
            if ($m.Disabled -and $m.MemberType -in 'user', 'inetOrgPerson', 'computer') { $sev = 'Low'; $finding = 'Disabled account still in privileged group' }

            New-ADAuditResult -Scanner 'Groups' -Target $m.MemberName -Severity $sev -Finding $finding -Data ([ordered]@{
                Check = 'PrivilegedMember'; Group = $pg.Label; Member = $m.MemberName; MemberType = $m.MemberType
                Membership = $(if ($m.Direct) { 'Direct' } else { 'Nested' }); Disabled = $m.Disabled; NestingDepth = $null; DistinguishedName = $m.MemberDN
            })
        }
    }

    # ---- Nesting depth and cycles ----
    $parents = @{}
    foreach ($g in $Groups) { $parents[$g.DistinguishedName] = $g.MemberOf }
    $memo = @{}
    $visiting = New-Object 'System.Collections.Generic.List[string]'
    $cycles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $Groups) { [void](Get-ADAuditGroupDepth -Dn $g.DistinguishedName -Parents $parents -Memo $memo -Visiting $visiting -Cycles $cycles) }

    foreach ($g in $Groups) {
        $depth = $memo[$g.DistinguishedName]
        $inCycle = $cycles.Contains($g.DistinguishedName)
        if ($inCycle) {
            $sev = 'Medium'; $finding = 'Circular group nesting'
        }
        elseif ($depth -gt $MaxNestingDepth) {
            $sev = 'Low'; $finding = "Nested $depth levels deep (limit $MaxNestingDepth)"
        }
        else { continue }
        New-ADAuditResult -Scanner 'Groups' -Target $g.SamAccountName -Severity $sev -Finding $finding -Data ([ordered]@{
            Check = 'Nesting'; Group = $g.SamAccountName; Member = $null; MemberType = 'group'; Membership = $null; Disabled = $null; NestingDepth = $depth; DistinguishedName = $g.DistinguishedName
        })
    }
}
