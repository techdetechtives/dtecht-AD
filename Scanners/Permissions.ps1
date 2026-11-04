#Requires -Version 5.1
<#
    Permissions (AD_Miner-style ACL checks, one hop, no BloodHound needed)
    Reads owner + DACL (nTSecurityDescriptor) of key objects over LDAP and reports
    principals that are NOT Tier 0 but hold rights that lead to domain compromise:

      DCSync          DS-Replication-Get-Changes(-All) on the domain root
      Tier-0 ACLs     GenericAll / WriteDacl / WriteOwner / write all properties /
                      all extended rights, plus object-specific rights (add member,
                      reset password, add key credential (shadow creds), write SPN,
                      RBCD, logon script, altSecurityIdentities) on: domain root,
                      AdminSDHolder, Domain Controllers OU, DC computers, krbtgt,
                      privileged groups and their members
      Owners          non-Tier-0 owner of any of those objects (owners can rewrite the ACL)
      GPOs            who can edit GPO objects (LDAP) and GPO folders in SYSVOL;
                      High when the GPO applies to DCs or the whole domain
      LAPS readers    who can read LAPS passwords on the domain root, OUs and CN=Computers
      gMSA readers    who can retrieve gMSA passwords (msDS-GroupMSAMembership)

    Only Allow ACEs are evaluated; Deny ACEs are ignored, so a finding may be
    blocked by a Deny in rare cases. Group membership of the principal is not
    expanded (one hop) - check who is in a flagged group.
#>

$script:ADAuditBroadSids = @{
    'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-7' = 'Anonymous'
    'S-1-5-32-545' = 'Users'; 'S-1-5-2' = 'Network'; 'S-1-5-4' = 'Interactive'
}
$script:ADAuditBroadRids = @{ '513' = 'Domain Users'; '514' = 'Domain Guests'; '515' = 'Domain Computers' }
$script:ADAuditWellKnownNames = @{
    'S-1-5-18' = 'SYSTEM'; 'S-1-5-10' = 'SELF'; 'S-1-3-0' = 'CREATOR OWNER'; 'S-1-5-9' = 'Enterprise Domain Controllers'
    'S-1-5-32-544' = 'BUILTIN\Administrators'; 'S-1-5-32-548' = 'Account Operators'; 'S-1-5-32-549' = 'Server Operators'
    'S-1-5-32-550' = 'Print Operators'; 'S-1-5-32-551' = 'Backup Operators'; 'S-1-5-32-554' = 'Pre-Windows 2000 Compatible Access'
    'S-1-5-32-560' = 'Windows Authorization Access Group'; 'S-1-5-32-561' = 'Terminal Server License Servers'
}

function Test-ADAuditBroadSid {
    param([string]$Sid)
    if ($script:ADAuditBroadSids.ContainsKey($Sid)) { return $true }
    return ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$') -and $script:ADAuditBroadRids.ContainsKey($Matches[1])
}

function New-ADAuditSidResolver {
    <# Resolver context for Resolve-ADAuditSid (keeps a cache) #>
    param([string]$Server, [pscredential]$Credential, [string]$DomainSid, [string]$NetbiosName)
    [pscustomobject]@{ Server = $Server; Credential = $Credential; DomainSid = $DomainSid; Netbios = $NetbiosName; Cache = @{} }
}

function Resolve-ADAuditSid {
    <# 'S-1-...' -> 'DOMAIN\name' via well-known table, Windows lookup, then LDAP; falls back to the SID #>
    param([Parameter(Mandatory)]$Resolver, [string]$Sid)
    if (-not $Sid) { return $null }
    $cache = $Resolver.Cache
    if ($cache.ContainsKey($Sid)) { return $cache[$Sid] }
    $ridNames = @{ '512' = 'Domain Admins'; '513' = 'Domain Users'; '514' = 'Domain Guests'; '515' = 'Domain Computers'; '516' = 'Domain Controllers'; '517' = 'Cert Publishers'; '518' = 'Schema Admins'; '519' = 'Enterprise Admins'; '520' = 'Group Policy Creator Owners'; '521' = 'Read-only Domain Controllers'; '526' = 'Key Admins'; '527' = 'Enterprise Key Admins'; '553' = 'RAS and IAS Servers' }
    $name = $null
    if ($script:ADAuditWellKnownNames.ContainsKey($Sid)) { $name = $script:ADAuditWellKnownNames[$Sid] }
    elseif ($script:ADAuditBroadSids.ContainsKey($Sid)) { $name = $script:ADAuditBroadSids[$Sid] }
    if (-not $name) {
        try { $name = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
    }
    if (-not $name) {
        try {
            $o = Invoke-ADAuditLdapQuery -Server $Resolver.Server -Credential $Resolver.Credential -Filter "(objectSid=$Sid)" -Properties 'sAMAccountName' | Select-Object -First 1
            if ($o.sAMAccountName) { $name = "$($Resolver.Netbios)\$($o.sAMAccountName)" }
        }
        catch { }
    }
    if (-not $name -and $Resolver.DomainSid -and $Sid -match "^$([regex]::Escape($Resolver.DomainSid))-(\d+)$" -and $ridNames.ContainsKey($Matches[1])) { $name = "$($Resolver.Netbios)\$($ridNames[$Matches[1]])" }
    if (-not $name) { $name = $Sid }
    $cache[$Sid] = $name
    return $name
}

function Get-ADAuditTier0Sids {
    <# SIDs whose rights on Tier-0 objects are expected (Tier 0 themselves, or built-in plumbing) #>
    param([string]$DomainSid, [string]$RootDomainSid, $Privileged)
    $t = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in 'S-1-5-18', 'S-1-5-10', 'S-1-3-0', 'S-1-5-9', 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551') { [void]$t.Add($s) }
    foreach ($r in 512, 516, 518, 519, 520, 521, 526, 527, 498) {
        if ($DomainSid) { [void]$t.Add("$DomainSid-$r") }
        if ($RootDomainSid) { [void]$t.Add("$RootDomainSid-$r") }
    }
    if ($Privileged -and $Privileged.Sids) { foreach ($s in $Privileged.Sids) { [void]$t.Add($s) } }
    return , $t
}

function Get-ADAuditObjectKind {
    param([object[]]$ObjectClass)
    $c = @($ObjectClass | ForEach-Object { [string]$_ })
    if ($c -contains 'domainDNS') { return 'Domain' }
    if ($c -contains 'groupPolicyContainer') { return 'GPO' }
    if ($c -contains 'computer') { return 'Computer' }
    if ($c -contains 'group') { return 'Group' }
    if ($c -contains 'user') { return 'User' }
    if ($c -contains 'organizationalUnit') { return 'OU' }
    return 'Container'
}

function Get-ADAuditDangerousAce {
    <#
        Groups dangerous rights per principal for one object.
        Returns objects: Sid, Rights (string[]), Inherited (bool: all ACEs inherited)
    #>
    param([Parameter(Mandatory)]$Parsed, [Parameter(Mandatory)][string]$Kind, $TrustedSids)
    $by = [ordered]@{}
    foreach ($a in $Parsed.Aces) {
        if (-not $a.Sid -or ($TrustedSids -and $TrustedSids.Contains($a.Sid))) { continue }
        $rights = @(Get-ADAuditAceRight -Ace $a -Kind $Kind)
        if (-not $rights) { continue }
        if (-not $by.Contains($a.Sid)) { $by[$a.Sid] = @{ Rights = New-Object System.Collections.Generic.List[string]; Inherited = $true } }
        foreach ($r in $rights) { if (-not $by[$a.Sid].Rights.Contains($r)) { $by[$a.Sid].Rights.Add($r) } }
        if (-not $a.Inherited) { $by[$a.Sid].Inherited = $false }
    }
    foreach ($k in $by.Keys) { [pscustomobject]@{ Sid = $k; Rights = $by[$k].Rights.ToArray(); Inherited = $by[$k].Inherited } }
}

function Invoke-ADAuditPermissionScan {
    [CmdletBinding()]
    param(
        $Privileged,
        [string]$Server,
        [pscredential]$Credential,
        [switch]$SkipSysvol
    )

    $rootDse = Get-ADAuditRootDse -Server $Server -Credential $Credential
    $nc = $rootDse.DefaultNamingContext
    $config = $rootDse.ConfigurationNamingContext
    $domain = ConvertTo-ADAuditDnsName $nc

    $domObj = Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase $nc -Scope Base -Filter '(objectClass=*)' -Properties 'objectSid', 'objectClass', 'distinguishedName', 'gPLink' -SecurityDescriptor | Select-Object -First 1
    $domainSid = ConvertTo-ADAuditSidString $domObj.objectSid
    $rootSid = $domainSid
    if ($rootDse.RootDomainNamingContext -and $rootDse.RootDomainNamingContext -ne $nc) {
        try { $rootSid = ConvertTo-ADAuditSidString ((Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase $rootDse.RootDomainNamingContext -Scope Base -Filter '(objectClass=*)' -Properties 'objectSid' | Select-Object -First 1).objectSid) } catch { }
    }
    $netbios = $null
    try {
        $netbios = [string](Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase "CN=Partitions,$config" -Filter "(&(objectClass=crossRef)(nCName=$(ConvertTo-ADAuditLdapFilterValue $nc)))" -Properties 'nETBIOSName' | Select-Object -First 1).nETBIOSName
    }
    catch { }
    if (-not $netbios) { $netbios = ($domain -split '\.')[0].ToUpperInvariant() }

    $trusted = Get-ADAuditTier0Sids -DomainSid $domainSid -RootDomainSid $rootSid -Privileged $Privileged
    $resolve = New-ADAuditSidResolver -Server $Server -Credential $Credential -DomainSid $domainSid -NetbiosName $netbios

    function Out-Perm([string]$Target, [string]$Severity, [string]$Finding, [System.Collections.IDictionary]$Data) {
        New-ADAuditResult -Scanner 'Permissions' -Target $Target -Severity $Severity -Finding $Finding -Data $Data
    }
    function Get-Parsed($obj) {
        $b = $obj.nTSecurityDescriptor
        if (-not $b) { return $null }
        try { return ConvertFrom-ADAuditSecurityDescriptor -Bytes ([byte[]]$b) } catch { return $null }
    }
    function Out-Tier0Object($obj, [string]$Label, [string]$Kind) {
        $dn = [string]$obj.distinguishedName
        $parsed = Get-Parsed $obj
        if (-not $parsed) {
            Out-Perm $Label 'Info' 'Security descriptor not readable' ([ordered]@{ Check = 'ACL'; ObjectDN = $dn })
            return
        }
        if ($parsed.OwnerSid -and -not $trusted.Contains($parsed.OwnerSid)) {
            $who = Resolve-ADAuditSid -Resolver $resolve -Sid $parsed.OwnerSid
            $broad = Test-ADAuditBroadSid $parsed.OwnerSid
            Out-Perm $Label 'High' "Non-Tier-0 owner: $who$(if ($broad) { ' (broad group!)' }) - owners can rewrite the ACL" ([ordered]@{
                Check = 'Owner'; Principal = $who; PrincipalSid = $parsed.OwnerSid; Rights = 'Owner'; ObjectKind = $Kind; ObjectDN = $dn
            })
        }
        $k = $(if ($Kind -eq 'AdminSDHolder') { 'AdminSDHolder' } else { $Kind })
        foreach ($d in (Get-ADAuditDangerousAce -Parsed $parsed -Kind $k -TrustedSids $trusted)) {
            $rights = @($d.Rights | Where-Object { $_ -notin 'GetChanges', 'GetChangesAll', 'GetChangesInFilteredSet' })   # DCSync reported separately
            if (-not $rights) { continue }
            $who = Resolve-ADAuditSid -Resolver $resolve -Sid $d.Sid
            $broad = Test-ADAuditBroadSid $d.Sid
            Out-Perm $Label 'High' "Dangerous rights for non-Tier-0 $who$(if ($broad) { ' (broad group!)' }): $($rights -join ', ')" ([ordered]@{
                Check = 'ACL'; Principal = $who; PrincipalSid = $d.Sid; Rights = ($rights -join ', '); ObjectKind = $Kind; Inherited = $d.Inherited; ObjectDN = $dn
            })
        }
    }

    # ---------- 1. Domain root: DCSync + ACL ----------
    $parsedDomain = Get-Parsed $domObj
    if ($parsedDomain) {
        $repl = [ordered]@{}
        foreach ($a in $parsedDomain.Aces) {
            if (-not $a.Sid -or $trusted.Contains($a.Sid)) { continue }
            foreach ($r in (Get-ADAuditAceRight -Ace $a -Kind 'Domain')) {
                if ($r -in 'GetChanges', 'GetChangesAll', 'GenericAll', 'AllExtendedRights') {
                    if (-not $repl.Contains($a.Sid)) { $repl[$a.Sid] = New-Object 'System.Collections.Generic.HashSet[string]' }
                    [void]$repl[$a.Sid].Add($r)
                }
            }
        }
        foreach ($sid in $repl.Keys) {
            $r = $repl[$sid]
            $full = $r.Contains('GenericAll') -or $r.Contains('AllExtendedRights') -or ($r.Contains('GetChanges') -and $r.Contains('GetChangesAll'))
            $who = Resolve-ADAuditSid -Resolver $resolve -Sid $sid
            $isSync = $who -match '(?i)\\(MSOL_|AAD_|Sync_|ADSync)'
            if ($full) {
                $sev = $(if ($isSync) { 'Medium' } else { 'High' })
                $msg = "Can DCSync (dump all password hashes): $who"
                if ($isSync) { $msg += ' - looks like the Entra Connect sync account; expected, but it is Tier 0' }
            }
            elseif ($r.Contains('GetChangesAll')) { $sev = 'Medium'; $msg = "Has Replicating Directory Changes All (one right short of DCSync): $who" }
            else { continue }
            Out-Perm $domain $sev $msg ([ordered]@{ Check = 'DCSync'; Principal = $who; PrincipalSid = $sid; Rights = (@($r) -join ', '); ObjectKind = 'Domain'; ObjectDN = $nc })
        }
        Out-Tier0Object $domObj $domain 'Domain'
    }
    else { Out-Perm $domain 'Info' 'Domain root security descriptor not readable' ([ordered]@{ Check = 'ACL'; ObjectDN = $nc }) }

    # ---------- 2. Other Tier-0 objects ----------
    $props = 'distinguishedName', 'objectClass', 'sAMAccountName', 'name'
    $tier0 = New-Object System.Collections.ArrayList
    foreach ($spec in @(
            @{ Base = "CN=AdminSDHolder,CN=System,$nc"; Label = 'AdminSDHolder'; Kind = 'AdminSDHolder' },
            @{ Base = "OU=Domain Controllers,$nc"; Label = 'OU=Domain Controllers'; Kind = 'OU' })) {
        try {
            $o = Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase $spec.Base -Scope Base -Filter '(objectClass=*)' -Properties $props -SecurityDescriptor | Select-Object -First 1
            if ($o) { [void]$tier0.Add(@{ Obj = $o; Label = $spec.Label; Kind = $spec.Kind }) }
        }
        catch { Out-Perm $spec.Label 'Info' "Not readable: $($_.Exception.Message)" ([ordered]@{ Check = 'ACL'; ObjectDN = $spec.Base }) }
    }
    $dcFilter = '(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864)))'
    foreach ($o in (Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase $nc -Filter $dcFilter -Properties $props -SecurityDescriptor)) {
        [void]$tier0.Add(@{ Obj = $o; Label = [string]$o.sAMAccountName; Kind = 'Computer' })
    }
    if ($domainSid) {
        foreach ($o in (Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase $nc -Filter "(objectSid=$domainSid-502)" -Properties $props -SecurityDescriptor)) {
            [void]$tier0.Add(@{ Obj = $o; Label = 'krbtgt'; Kind = 'User' })
        }
    }
    $seenDn = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($t in $tier0) { [void]$seenDn.Add([string]$t.Obj.distinguishedName) }
    if ($Privileged) {
        $dns = @($Privileged.Groups | ForEach-Object { $_.DistinguishedName }) + @($Privileged.Members | ForEach-Object { $_.MemberDN })
        foreach ($dn in ($dns | Select-Object -Unique)) {
            if (-not $dn -or $seenDn.Contains($dn)) { continue }
            if ($dn -match '^CN=S-1-') { continue }   # foreign security principals
            try {
                $o = Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase $dn -Scope Base -Filter '(objectClass=*)' -Properties $props -SecurityDescriptor | Select-Object -First 1
                if ($o) {
                    [void]$seenDn.Add($dn)
                    [void]$tier0.Add(@{ Obj = $o; Label = $(if ($o.sAMAccountName) { [string]$o.sAMAccountName } else { [string]$o.name }); Kind = (Get-ADAuditObjectKind $o.objectClass) })
                }
            }
            catch { }
        }
    }
    foreach ($t in $tier0) { Out-Tier0Object $t.Obj $t.Label $t.Kind }

    # ---------- 3. GPOs (AD object + SYSVOL folder) ----------
    $ouObj = Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase "OU=Domain Controllers,$nc" -Scope Base -Filter '(objectClass=*)' -Properties 'gPLink' | Select-Object -First 1
    $tier0Gpo = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($l in @(ConvertFrom-ADAuditGpLink ([string]$domObj.gPLink)) + @(ConvertFrom-ADAuditGpLink ([string]$ouObj.gPLink))) { if (-not $l.Disabled) { [void]$tier0Gpo.Add($l.GpoDN) } }

    foreach ($g in (Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase "CN=Policies,CN=System,$nc" -Filter '(objectClass=groupPolicyContainer)' -Properties 'distinguishedName', 'displayName', 'gPCFileSysPath' -SecurityDescriptor)) {
        $dn = [string]$g.distinguishedName
        $name = [string]$g.displayName
        $isT0 = $tier0Gpo.Contains($dn)
        $scope = $(if ($isT0) { 'applies to DCs or the whole domain' } else { 'other GPO' })
        $sev = $(if ($isT0) { 'High' } else { 'Medium' })
        $parsed = Get-Parsed $g
        if ($parsed) {
            if ($parsed.OwnerSid -and -not $trusted.Contains($parsed.OwnerSid)) {
                $who = Resolve-ADAuditSid -Resolver $resolve -Sid $parsed.OwnerSid
                Out-Perm $name $sev "GPO owned by non-Tier-0 $who ($scope)" ([ordered]@{ Check = 'GPOOwner'; Principal = $who; PrincipalSid = $parsed.OwnerSid; Rights = 'Owner'; ObjectKind = 'GPO'; Tier0Gpo = $isT0; ObjectDN = $dn })
            }
            foreach ($d in (Get-ADAuditDangerousAce -Parsed $parsed -Kind 'GPO' -TrustedSids $trusted)) {
                $who = Resolve-ADAuditSid -Resolver $resolve -Sid $d.Sid
                $broad = Test-ADAuditBroadSid $d.Sid
                Out-Perm $name $(if ($broad) { 'High' } else { $sev }) "Can edit GPO: $who$(if ($broad) { ' (broad group!)' }) - $($d.Rights -join ', ') ($scope)" ([ordered]@{
                    Check = 'GPOEdit'; Principal = $who; PrincipalSid = $d.Sid; Rights = ($d.Rights -join ', '); ObjectKind = 'GPO'; Tier0Gpo = $isT0; ObjectDN = $dn
                })
            }
        }

        $path = [string]$g.gPCFileSysPath
        if (-not $SkipSysvol -and $path) {
            try {
                $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
                $bad = [ordered]@{}
                foreach ($r in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                    if ($r.AccessControlType -ne 'Allow') { continue }
                    $sid = $r.IdentityReference.Value
                    if ($trusted.Contains($sid)) { continue }
                    $m = [int64]$r.FileSystemRights
                    # WriteData/AppendData/Delete/ChangePermissions/TakeOwnership or generic write/all
                    if (($m -band (0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)) -ne 0) { $bad[$sid] = "$($r.FileSystemRights)" }
                }
                foreach ($sid in $bad.Keys) {
                    $who = Resolve-ADAuditSid -Resolver $resolve -Sid $sid
                    $broad = Test-ADAuditBroadSid $sid
                    Out-Perm $name $(if ($broad) { 'High' } else { $sev }) "Can modify GPO files in SYSVOL: $who$(if ($broad) { ' (broad group!)' }) - $($bad[$sid]) ($scope)" ([ordered]@{
                        Check = 'SysvolEdit'; Principal = $who; PrincipalSid = $sid; Rights = $bad[$sid]; ObjectKind = 'GPO'; Tier0Gpo = $isT0; ObjectDN = $path
                    })
                }
            }
            catch { Out-Perm $name 'Info' "SYSVOL folder ACL not readable: $($_.Exception.Message)" ([ordered]@{ Check = 'SysvolEdit'; ObjectDN = $path }) }
        }
    }

    # ---------- 4. Who can link GPOs to the domain root / DC OU ----------
    # (covered by Tier-0 ACL rows above: WriteGPLink is reported for Domain and OU kinds)

    # ---------- 5. LAPS password readers ----------
    $lapsGuids = @{}
    try {
        foreach ($a in (Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase "CN=Schema,$config" -Filter '(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password)(lDAPDisplayName=msLAPS-EncryptedPassword))' -Properties 'lDAPDisplayName', 'schemaIDGUID')) {
            if ($a.schemaIDGUID) { $lapsGuids[([Guid]::new([byte[]]$a.schemaIDGUID)).ToString()] = [string]$a.lDAPDisplayName }
        }
    }
    catch { }
    if ($lapsGuids.Count -gt 0) {
        $containers = @($domObj)
        $containers += @(Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase $nc -Filter '(objectCategory=organizationalUnit)' -Properties 'distinguishedName', 'objectClass' -SecurityDescriptor)
        try { $containers += @(Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase "CN=Computers,$nc" -Scope Base -Filter '(objectClass=*)' -Properties 'distinguishedName', 'objectClass' -SecurityDescriptor) } catch { }
        $computerGuid = $script:ADAuditClassGuid.computer
        $readers = [ordered]@{}
        foreach ($c in $containers) {
            $parsed = Get-Parsed $c
            if (-not $parsed) { continue }
            foreach ($a in $parsed.Aces) {
                if (-not $a.Sid -or $trusted.Contains($a.Sid) -or -not (Test-ADAuditAceInheritsTo -Ace $a -ClassGuid $computerGuid)) { continue }
                if ($a.Inherited) { continue }   # report where the delegation is set, not every OU it flows into
                $m = [int64]$a.Mask
                $ga = ($m -band 0x10000000) -or (($m -band 0xF01FF) -eq 0xF01FF)
                $cr = ($m -band 0x100) -and ((-not $a.ObjectType) -or $lapsGuids.ContainsKey($a.ObjectType))
                if (-not ($ga -or $cr)) { continue }
                $attr = $(if ($a.ObjectType -and $lapsGuids.ContainsKey($a.ObjectType)) { $lapsGuids[$a.ObjectType] } elseif ($ga) { 'GenericAll' } else { 'AllExtendedRights' })
                $key = "$($a.Sid)|$($c.distinguishedName)"
                if (-not $readers.Contains($key)) { $readers[$key] = @{ Sid = $a.Sid; DN = [string]$c.distinguishedName; Attrs = New-Object 'System.Collections.Generic.HashSet[string]' } }
                [void]$readers[$key].Attrs.Add($attr)
            }
        }
        foreach ($r in $readers.Values) {
            $who = Resolve-ADAuditSid -Resolver $resolve -Sid $r.Sid
            $broad = Test-ADAuditBroadSid $r.Sid
            Out-Perm $r.DN $(if ($broad) { 'High' } else { 'Low' }) "Can read LAPS passwords of computers below: $who$(if ($broad) { ' (broad group!)' })" ([ordered]@{
                Check = 'LapsRead'; Principal = $who; PrincipalSid = $r.Sid; Rights = (@($r.Attrs) -join ', '); ObjectKind = 'OU'; ObjectDN = $r.DN
            })
        }
    }

    # ---------- 6. gMSA password readers ----------
    try {
        foreach ($g in (Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase $nc -Filter '(objectClass=msDS-GroupManagedServiceAccount)' -Properties 'sAMAccountName', 'distinguishedName', 'msDS-GroupMSAMembership')) {
            $b = $g.'msDS-GroupMSAMembership'
            if (-not $b) { continue }
            $isPrivGmsa = $Privileged -and $Privileged.MapByMember.ContainsKey([string]$g.distinguishedName)
            $parsed = $null
            try { $parsed = ConvertFrom-ADAuditSecurityDescriptor -Bytes ([byte[]]$b) } catch { continue }
            foreach ($a in $parsed.Aces) {
                if (-not $a.Allow -or -not $a.Sid) { continue }
                $who = Resolve-ADAuditSid -Resolver $resolve -Sid $a.Sid
                $broad = Test-ADAuditBroadSid $a.Sid
                $isTrusted = $trusted.Contains($a.Sid)
                if ($isTrusted) { continue }
                $sev = $(if ($broad) { 'High' } elseif ($isPrivGmsa -and -not $isTrusted) { 'High' } else { 'Info' })
                $msg = $(if ($isPrivGmsa -and -not $isTrusted) { "Non-Tier-0 $who can read the password of privileged gMSA" } elseif ($broad) { "Broad group $who can read gMSA password" } else { "Can read gMSA password: $who" })
                Out-Perm ([string]$g.sAMAccountName) $sev $msg ([ordered]@{ Check = 'GmsaRead'; Principal = $who; PrincipalSid = $a.Sid; ObjectKind = 'gMSA'; PrivilegedGmsa = [bool]$isPrivGmsa; ObjectDN = [string]$g.distinguishedName })
            }
        }
    }
    catch { Out-Perm '(gMSA)' 'Info' "gMSA query failed: $($_.Exception.Message)" ([ordered]@{ Check = 'GmsaRead' }) }
}
