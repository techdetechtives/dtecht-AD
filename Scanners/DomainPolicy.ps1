#Requires -Version 5.1
<#
    DomainPolicy (PingCastle equivalents: domain-level stale/privileged/anomaly rules)
    AD-only. Reads the domain object and a few well-known accounts/groups:

      Default password policy (length, history, max age), account lockout
      ms-DS-MachineAccountQuota (who can join computers)
      krbtgt password age, Guest account enabled
      'Pre-Windows 2000 Compatible Access' containing Anonymous / Everyone
      Domain functional level, number of fine-grained password policies
#>

function Invoke-ADAuditDomainPolicyScan {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential, [int]$KrbtgtMaxAgeDays = 180, $Privileged, [int]$AdminMinPasswordLength = 14)

    $nc = Get-ADAuditDefaultNamingContext -Server $Server -Credential $Credential
    $domain = ConvertTo-ADAuditDnsName $nc
    $props = 'objectSid', 'minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'lockoutThreshold', 'ms-DS-MachineAccountQuota', 'msDS-Behavior-Version'
    $d = Invoke-ADAuditLdapQuery -Server $Server -SearchBase $nc -Credential $Credential -Filter '(objectClass=domainDNS)' -Scope Base -Properties $props | Select-Object -First 1
    $domainSid = ConvertTo-ADAuditSidString $d.objectSid

    function Out-Setting([string]$Setting, $Value, [string]$Severity, [string]$Finding) {
        New-ADAuditResult -Scanner 'DomainPolicy' -Target $domain -Severity $Severity -Finding $Finding -Data ([ordered]@{ Setting = $Setting; Value = $Value })
    }

    $minLen = [int]$d.minPwdLength
    Out-Setting 'MinimumPasswordLength' $minLen $(if ($minLen -lt 8) { 'High' } elseif ($minLen -lt 12) { 'Medium' } else { 'OK' }) $(if ($minLen -lt 12) { "Default policy minimum length is $minLen (recommend 12+ or FGPP)" } else { '' })

    $hist = [int]$d.pwdHistoryLength
    Out-Setting 'PasswordHistoryLength' $hist $(if ($hist -lt 12) { 'Low' } else { 'OK' }) $(if ($hist -lt 12) { "Password history is $hist" } else { '' })

    $maxAgeDays = $null
    if ($null -ne $d.maxPwdAge) {
        $raw = [Int64]"$($d.maxPwdAge)"
        if ($raw -ne 0 -and $raw -ne [Int64]::MinValue) { $maxAgeDays = [int]([math]::Abs($raw) / 864000000000) }
    }
    Out-Setting 'MaximumPasswordAgeDays' $(if ($null -eq $maxAgeDays) { 'Never' } else { $maxAgeDays }) 'Info' ''

    $lock = [int]$d.lockoutThreshold
    Out-Setting 'LockoutThreshold' $lock $(if ($lock -eq 0) { 'Medium' } else { 'OK' }) $(if ($lock -eq 0) { 'No account lockout (password spraying is unthrottled)' } else { '' })

    $maq = $d.'ms-DS-MachineAccountQuota'
    if ($null -ne $maq) {
        $maq = [int]$maq
        Out-Setting 'MachineAccountQuota' $maq $(if ($maq -gt 0) { 'Medium' } else { 'OK' }) $(if ($maq -gt 0) { "Any authenticated user can join up to $maq computers" } else { '' })
    }

    $levels = @{ 0 = '2000'; 1 = '2003 interim'; 2 = '2003'; 3 = '2008'; 4 = '2008 R2'; 5 = '2012'; 6 = '2012 R2'; 7 = '2016'; 10 = '2025' }
    $fl = [int]$d.'msDS-Behavior-Version'
    $flName = $(if ($levels.ContainsKey($fl)) { $levels[$fl] } else { "$fl" })
    Out-Setting 'DomainFunctionalLevel' $flName $(if ($fl -lt 6) { 'Low' } else { 'Info' }) $(if ($fl -lt 6) { "Functional level $flName blocks newer protections (e.g. Protected Users DC-side)" } else { '' })

    # Fine-grained password policies: one row each, and whether admins get a stronger policy
    try {
        $psoProps = 'name', 'msDS-PasswordSettingsPrecedence', 'msDS-MinimumPasswordLength', 'msDS-LockoutThreshold', 'msDS-PasswordReversibleEncryptionEnabled', 'msDS-PSOAppliesTo'
        $pso = @(Invoke-ADAuditLdapQuery -Server $Server -SearchBase "CN=Password Settings Container,CN=System,$nc" -Credential $Credential -Filter '(objectClass=msDS-PasswordSettings)' -Properties $psoProps)
        Out-Setting 'FineGrainedPasswordPolicies' $pso.Count 'Info' $(if ($pso.Count -gt 0) { (($pso | ForEach-Object { $_.name }) -join ', ') } else { 'None (or not readable)' })

        # DNs that make a PSO an "admin" policy: privileged global groups (PSOs only apply via global groups) and privileged accounts
        $adminDns = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        if ($Privileged) {
            foreach ($g in $Privileged.Groups) { if ($g.Label -in 'Domain Admins', 'Enterprise Admins', 'Schema Admins') { [void]$adminDns.Add($g.DistinguishedName) } }
            foreach ($m in $Privileged.Members) { [void]$adminDns.Add($m.MemberDN) }
        }
        $adminCovered = $false
        foreach ($p in $pso) {
            $applies = @($p.'msDS-PSOAppliesTo' | Where-Object { $_ } | ForEach-Object { [string]$_ })
            $forAdmins = @($applies | Where-Object { $adminDns.Contains($_) }).Count -gt 0
            if ($forAdmins) { $adminCovered = $true }
            $len = [int]$p.'msDS-MinimumPasswordLength'
            $rev = "$($p.'msDS-PasswordReversibleEncryptionEnabled')" -eq 'True'
            $val = 'precedence {0}, min length {1}, lockout {2}, applies to {3}' -f $p.'msDS-PasswordSettingsPrecedence', $len, $p.'msDS-LockoutThreshold', $applies.Count
            if ($rev) { Out-Setting "FGPP:$($p.name)" $val 'High' 'Fine-grained policy enables reversible password encryption' }
            elseif ($forAdmins -and $len -lt $AdminMinPasswordLength) { Out-Setting "FGPP:$($p.name)" $val 'Medium' "Admin fine-grained policy minimum length is $len (recommend $AdminMinPasswordLength+)" }
            else { Out-Setting "FGPP:$($p.name)" $val $(if ($applies.Count -eq 0) { 'Low' } else { 'Info' }) $(if ($applies.Count -eq 0) { 'Fine-grained policy applies to nothing' } elseif ($forAdmins) { 'Applies to admins' } else { '' }) }
        }
        if ($Privileged -and -not $adminCovered -and $minLen -lt $AdminMinPasswordLength) {
            Out-Setting 'AdminPasswordPolicy' "default (min $minLen)" 'Low' "Admins only have the default password policy (min length $minLen) - add a fine-grained policy for admin groups"
        }
    }
    catch { Out-Setting 'FineGrainedPasswordPolicies' $null 'Info' 'Not readable' }

    if ($domainSid) {
        $k = Invoke-ADAuditLdapQuery -Server $Server -SearchBase $nc -Credential $Credential -Filter "(objectSid=$domainSid-502)" -Properties 'pwdLastSet' | Select-Object -First 1
        $kSet = ConvertFrom-ADAuditFileTime $k.pwdLastSet
        if ($kSet) {
            $age = [int]([DateTime]::UtcNow - $kSet).TotalDays
            Out-Setting 'KrbtgtPasswordAgeDays' $age $(if ($age -gt $KrbtgtMaxAgeDays) { 'Medium' } else { 'OK' }) $(if ($age -gt $KrbtgtMaxAgeDays) { "krbtgt password last changed $($kSet.ToString('yyyy-MM-dd'))" } else { '' })
        }

        $g = Invoke-ADAuditLdapQuery -Server $Server -SearchBase $nc -Credential $Credential -Filter "(objectSid=$domainSid-501)" -Properties 'userAccountControl', 'sAMAccountName' | Select-Object -First 1
        if ($g) {
            $enabled = (([int]$g.userAccountControl) -band 0x2) -eq 0
            Out-Setting 'GuestAccountEnabled' $enabled $(if ($enabled) { 'High' } else { 'OK' }) $(if ($enabled) { "Built-in Guest ($($g.sAMAccountName)) is enabled" } else { '' })
        }
    }

    $pre = Invoke-ADAuditLdapQuery -Server $Server -SearchBase $nc -Credential $Credential -Filter '(objectSid=S-1-5-32-554)' -Properties 'member' | Select-Object -First 1
    $members = @($pre.member | Where-Object { $_ })
    $bad = @($members | Where-Object { $_ -match '^CN=(S-1-5-7|S-1-1-0),' })
    $authUsers = @($members | Where-Object { $_ -match '^CN=S-1-5-11,' }).Count -gt 0
    if ($bad.Count -gt 0) { Out-Setting 'PreWindows2000CompatibleAccess' 'Anonymous/Everyone' 'Medium' 'Anonymous or Everyone in Pre-Windows 2000 Compatible Access (anonymous AD enumeration)' }
    else { Out-Setting 'PreWindows2000CompatibleAccess' $(if ($authUsers) { 'Authenticated Users' } else { "$($members.Count) members" }) 'OK' '' }
}
