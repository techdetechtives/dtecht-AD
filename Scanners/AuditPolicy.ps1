#Requires -Version 5.1
<#
    AuditPolicy
    Reads (never sets) the audit policy that Group Policy applies to domain controllers:

      1. Finds GPOs linked to the domain root and to OU=Domain Controllers (gPLink),
         honouring disabled links, enforced links, block inheritance and GPOs with
         computer settings disabled.
      2. Reads each GPO's files from SYSVOL:
           Machine\Microsoft\Windows NT\Audit\audit.csv     (advanced audit policy)
           Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf (legacy [Event Audit], [Security Log])
      3. Works out the winning value per subcategory and flags subcategories that
         AD security monitoring (and the Events scanner) depends on.

    Limits: GPOs linked to AD sites, local policy and auditpol changes made by hand
    are not visible here. Confirm on a DC with:  auditpol /get /category:*
    SYSVOL is read over SMB with the current Windows logon, not -Credential.
#>

$script:ADAuditSubcategories = [ordered]@{
    # GUID suffix -69AE-11D9-BED3-505054503030
    '0CCE923F' = @{ Name = 'Credential Validation'; Category = 'Account Logon'; Need = 3; Why = 'NTLM auth on DCs (4776), password spraying' }
    '0CCE9242' = @{ Name = 'Kerberos Authentication Service'; Category = 'Account Logon'; Need = 3; Why = 'TGT requests (4768/4771), AS-REP roasting, spraying' }
    '0CCE9240' = @{ Name = 'Kerberos Service Ticket Operations'; Category = 'Account Logon'; Need = 3; Why = 'Service tickets (4769), Kerberoasting' }
    '0CCE9235' = @{ Name = 'User Account Management'; Category = 'Account Management'; Need = 3; Why = 'Account create/change/delete, resets, SID history, DSRM (4720-4738, 4765, 4794)' }
    '0CCE9236' = @{ Name = 'Computer Account Management'; Category = 'Account Management'; Need = 1; Why = 'Computer accounts created/changed (4741/4742), MachineAccountQuota abuse' }
    '0CCE9237' = @{ Name = 'Security Group Management'; Category = 'Account Management'; Need = 1; Why = 'Group membership changes incl. Domain Admins (4728/4732/4756)' }
    '0CCE923A' = @{ Name = 'Other Account Management Events'; Category = 'Account Management'; Need = 1; Why = 'Password policy checks (4782, 4793)' }
    '0CCE923B' = @{ Name = 'Directory Service Access'; Category = 'DS Access'; Need = 3; Why = 'Object access (4662), DCSync detection' }
    '0CCE923C' = @{ Name = 'Directory Service Changes'; Category = 'DS Access'; Need = 1; Why = 'Attribute changes (5136): SPN, delegation, shadow credentials, ACLs' }
    '0CCE9215' = @{ Name = 'Logon'; Category = 'Logon/Logoff'; Need = 3; Why = 'Logons on DCs (4624/4625)' }
    '0CCE9217' = @{ Name = 'Account Lockout'; Category = 'Logon/Logoff'; Need = 2; Why = 'Failed logons to locked accounts (4625)' }
    '0CCE921B' = @{ Name = 'Special Logon'; Category = 'Logon/Logoff'; Need = 1; Why = 'Privileged logons (4672)' }
    '0CCE922F' = @{ Name = 'Audit Policy Change'; Category = 'Policy Change'; Need = 1; Why = 'Someone turning auditing off (4719)' }
    '0CCE9230' = @{ Name = 'Authentication Policy Change'; Category = 'Policy Change'; Need = 1; Why = 'Trusts, Kerberos policy changes (4706, 4713, 4716)' }
    '0CCE9228' = @{ Name = 'Sensitive Privilege Use'; Category = 'Privilege Use'; Need = 3; Why = 'Use of sensitive privileges (4673/4674)' }
    '0CCE9211' = @{ Name = 'Security System Extension'; Category = 'System'; Need = 1; Why = 'New services / auth packages (4697, 4610-4614)' }
    '0CCE922B' = @{ Name = 'Process Creation'; Category = 'Detailed Tracking'; Need = 1; Why = 'Process execution on DCs (4688)' }
}

$script:ADAuditLegacyAuditKeys = @{
    'AuditSystemEvents'    = 'System'
    'AuditLogonEvents'     = 'Logon/Logoff'
    'AuditObjectAccess'    = 'Object Access'
    'AuditPrivilegeUse'    = 'Privilege Use'
    'AuditProcessTracking' = 'Detailed Tracking'
    'AuditPolicyChange'    = 'Policy Change'
    'AuditAccountManage'   = 'Account Management'
    'AuditDSAccess'        = 'DS Access'
    'AuditAccountLogon'    = 'Account Logon'
}

function ConvertTo-ADAuditAuditSettingText {
    param($Value)
    if ($null -eq $Value) { return 'Not configured' }
    switch ([int]$Value) { 0 { 'No Auditing' } 1 { 'Success' } 2 { 'Failure' } 3 { 'Success and Failure' } default { "Value $Value" } }
}

function ConvertFrom-ADAuditGpLink {
    <#
        gPLink = [LDAP://cn={GUID},cn=policies,...;0][LDAP://...;2]
        Options: 0 enabled, 1 link disabled, 2 enforced, 3 disabled+enforced.
        Entries are stored in reverse link order: the LAST entry is link order 1
        (highest precedence), so string order = lowest -> highest precedence.
    #>
    param([string]$GpLink)
    if (-not $GpLink) { return @() }
    foreach ($m in [regex]::Matches($GpLink, '\[LDAP://([^;\]]+);(\d+)\]')) {
        $opt = [int]$m.Groups[2].Value
        [pscustomobject]@{
            GpoDN    = $m.Groups[1].Value
            Disabled = (($opt -band 1) -ne 0)
            Enforced = (($opt -band 2) -ne 0)
        }
    }
}

function Read-ADAuditIniSection {
    param([string[]]$Lines, [string]$Section)
    $out = @{}
    $in = $false
    foreach ($l in $Lines) {
        $t = $l.Trim()
        if ($t -match '^\[(.+)\]$') { $in = ($Matches[1] -ieq $Section); continue }
        if ($in -and $t -match '^([^=;]+?)\s*=\s*(.*)$') { $out[$Matches[1]] = $Matches[2] }
    }
    return $out
}

function Get-ADAuditGpoAuditSettings {
    <#
        Reads one GPO's audit settings from SYSVOL. Returns:
          Advanced : GUID(8-char prefix, upper) -> setting value (0-3)
          Legacy   : category -> value (0-3)
          SecurityLogMaxKB, Error
    #>
    param([Parameter(Mandatory)][string]$FileSysPath)

    $adv = @{}; $legacy = @{}; $maxKb = $null; $errs = @()

    $auditCsv = Join-Path $FileSysPath 'Machine\Microsoft\Windows NT\Audit\audit.csv'
    try {
        if (Test-Path -LiteralPath $auditCsv) {
            foreach ($row in (Import-Csv -LiteralPath $auditCsv)) {
                $guid = [string]$row.'Subcategory GUID'
                $val = [string]$row.'Setting Value'
                if ($val -notmatch '^\d+$') { continue }
                if ($guid -match '\{?([0-9A-Fa-f]{8})-') { $adv[$Matches[1].ToUpperInvariant()] = [int]$val }
            }
        }
    }
    catch { $errs += "audit.csv: $($_.Exception.Message)" }

    $inf = Join-Path $FileSysPath 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    try {
        if (Test-Path -LiteralPath $inf) {
            $lines = Get-Content -LiteralPath $inf
            $ea = Read-ADAuditIniSection -Lines $lines -Section 'Event Audit'
            foreach ($k in $ea.Keys) {
                if ($script:ADAuditLegacyAuditKeys.ContainsKey($k) -and $ea[$k] -match '^\d+$') { $legacy[$script:ADAuditLegacyAuditKeys[$k]] = [int]$ea[$k] }
            }
            $sl = Read-ADAuditIniSection -Lines $lines -Section 'Security Log'
            if ($sl['MaximumLogSize'] -match '^\d+$') { $maxKb = [int]$sl['MaximumLogSize'] }
        }
    }
    catch { $errs += "GptTmpl.inf: $($_.Exception.Message)" }

    [pscustomobject]@{ Advanced = $adv; Legacy = $legacy; SecurityLogMaxKB = $maxKb; Error = ($errs -join '; ') }
}

function Invoke-ADAuditAuditPolicyScan {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential, [int]$MinSecurityLogMB = 1024)

    $nc = Get-ADAuditDefaultNamingContext -Server $Server -Credential $Credential
    $domain = ConvertTo-ADAuditDnsName $nc
    $dcOu = "OU=Domain Controllers,$nc"

    $domObj = Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase $nc -Scope Base -Filter '(objectClass=*)' -Properties 'gPLink' | Select-Object -First 1
    $ouObj = Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase $dcOu -Scope Base -Filter '(objectClass=*)' -Properties 'gPLink', 'gPOptions' | Select-Object -First 1
    $blockInheritance = ($null -ne $ouObj.gPOptions) -and (([int]$ouObj.gPOptions -band 1) -ne 0)

    $gpos = @{}
    foreach ($g in (Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase "CN=Policies,CN=System,$nc" -Filter '(objectClass=groupPolicyContainer)' -Properties 'distinguishedName', 'displayName', 'gPCFileSysPath', 'flags')) {
        $gpos[([string]$g.distinguishedName).ToLowerInvariant()] = $g
    }

    # Lowest -> highest precedence for computers in OU=Domain Controllers
    $domLinks = @(ConvertFrom-ADAuditGpLink ([string]$domObj.gPLink))
    $ouLinks = @(ConvertFrom-ADAuditGpLink ([string]$ouObj.gPLink))
    $ordered = @()
    if (-not $blockInheritance) { $ordered += $domLinks | Where-Object { -not $_.Enforced } | ForEach-Object { $_ | Add-Member -NotePropertyName Scope -NotePropertyValue 'Domain' -PassThru } }
    $ordered += $ouLinks | Where-Object { -not $_.Enforced } | ForEach-Object { $_ | Add-Member -NotePropertyName Scope -NotePropertyValue 'Domain Controllers OU' -PassThru }
    $ordered += $ouLinks | Where-Object { $_.Enforced } | ForEach-Object { $_ | Add-Member -NotePropertyName Scope -NotePropertyValue 'Domain Controllers OU (enforced)' -PassThru }
    $ordered += $domLinks | Where-Object { $_.Enforced } | ForEach-Object { $_ | Add-Member -NotePropertyName Scope -NotePropertyValue 'Domain (enforced)' -PassThru }

    $effAdv = @{}; $effLegacy = @{}; $logMax = $null
    $applied = @()
    foreach ($l in $ordered) {
        if ($l.Disabled) { continue }
        $g = $gpos[$l.GpoDN.ToLowerInvariant()]
        if (-not $g) {
            New-ADAuditResult -Scanner 'AuditPolicy' -Target $l.GpoDN -Severity 'Info' -Finding "Linked GPO not found or not readable ($($l.Scope))" -Data ([ordered]@{ Check = 'GPO' })
            continue
        }
        $flags = 0; if ($null -ne $g.flags) { $flags = [int]$g.flags }
        if (($flags -band 2) -ne 0) { continue }   # computer settings disabled
        $name = [string]$g.displayName
        $applied += "$name [$($l.Scope)]"

        $s = Get-ADAuditGpoAuditSettings -FileSysPath ([string]$g.gPCFileSysPath)
        if ($s.Error) {
            New-ADAuditResult -Scanner 'AuditPolicy' -Target $name -Severity 'Info' -Finding "Could not read GPO files: $($s.Error)" -Data ([ordered]@{ Check = 'GPO'; Path = [string]$g.gPCFileSysPath })
        }
        foreach ($k in $s.Advanced.Keys) { $effAdv[$k] = @{ Value = $s.Advanced[$k]; Gpo = $name } }
        foreach ($k in $s.Legacy.Keys) { $effLegacy[$k] = @{ Value = $s.Legacy[$k]; Gpo = $name } }
        if ($null -ne $s.SecurityLogMaxKB) { $logMax = @{ Value = $s.SecurityLogMaxKB; Gpo = $name } }
    }

    New-ADAuditResult -Scanner 'AuditPolicy' -Target $domain -Severity 'Info' -Finding $(if ($applied) { 'GPOs applied to DCs (lowest to highest precedence): ' + ($applied -join ' > ') } else { 'No GPOs apply to OU=Domain Controllers' }) -Data ([ordered]@{
        Check = 'Scope'; BlockInheritance = $blockInheritance
    })

    $anyAdvanced = $effAdv.Count -gt 0
    foreach ($guid in $script:ADAuditSubcategories.Keys) {
        $sc = $script:ADAuditSubcategories[$guid]
        $value = $null; $source = $null; $kind = $null
        if ($effAdv.ContainsKey($guid)) { $value = $effAdv[$guid].Value; $source = $effAdv[$guid].Gpo; $kind = 'Advanced' }
        elseif ($effLegacy.ContainsKey($sc.Category)) {
            $value = $effLegacy[$sc.Category].Value; $source = $effLegacy[$sc.Category].Gpo; $kind = 'Legacy category'
        }

        $need = [int]$sc.Need
        $have = $(if ($null -eq $value) { 0 } else { [int]$value })
        $missing = $need -band (-bnot $have)
        $sev = 'OK'; $finding = ''
        if ($missing -ne 0) {
            $what = @(); if ($missing -band 1) { $what += 'Success' }; if ($missing -band 2) { $what += 'Failure' }
            $sev = $(if ($missing -band 1) { 'Medium' } else { 'Low' })
            $finding = "$($what -join ' and ') not audited - $($sc.Why)"
            if ($null -eq $value) { $finding += ' (not set by any DC GPO; Windows default applies)' }
        }
        if ($kind -eq 'Legacy category' -and $anyAdvanced) { $finding = ($finding + ' [legacy category setting may be ignored because advanced audit policy is also configured]').Trim() }

        New-ADAuditResult -Scanner 'AuditPolicy' -Target $sc.Name -Severity $sev -Finding $finding -Data ([ordered]@{
            Check = 'Subcategory'; Category = $sc.Category
            Required = (ConvertTo-ADAuditAuditSettingText $need)
            Effective = (ConvertTo-ADAuditAuditSettingText $value)
            SetBy = $source; Source = $kind
        })
    }

    $sev = 'OK'; $finding = ''
    if ($null -eq $logMax) { $sev = 'Info'; $finding = 'Security log size not set under Security Settings > Event Log (an Administrative Templates setting may still set it; the Events scanner reports actual retention)' }
    elseif ($logMax.Value -lt ($MinSecurityLogMB * 1024)) { $sev = 'Low'; $finding = "Security log max size $([int]($logMax.Value / 1024)) MB (recommend $MinSecurityLogMB MB+ on DCs, or forward to SIEM)" }
    New-ADAuditResult -Scanner 'AuditPolicy' -Target 'Security log size' -Severity $sev -Finding $finding -Data ([ordered]@{
        Check = 'LogSize'; Effective = $(if ($logMax) { "$([int]($logMax.Value / 1024)) MB" } else { 'Not configured' }); SetBy = $(if ($logMax) { $logMax.Gpo } else { $null })
    })
}
