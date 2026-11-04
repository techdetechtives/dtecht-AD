#Requires -Version 5.1
<#
    DomainControllers
    AD-only (plus one DNS lookup per DC). Inventories every DC with its site,
    IP addresses, OS, RODC / Global Catalog status and FSMO roles.

    Flags:
      - Only one writable DC in the domain (no redundancy)
      - DC computer account not seen for -DcStaleDays (decommissioned without cleanup?)
      - FSMO role held by a deleted / unresolvable DC
      - Site server objects with no matching DC computer (leftover metadata)
#>

function Invoke-ADAuditDomainControllerScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Computers,
        [string]$Server,
        [pscredential]$Credential,
        [int]$DcStaleDays = 30
    )

    $rootDse = Get-ADAuditRootDse -Server $Server -Credential $Credential
    $nc = $rootDse.DefaultNamingContext
    $config = $rootDse.ConfigurationNamingContext
    $domain = ConvertTo-ADAuditDnsName $nc

    # Site server objects: CN=<DC>,CN=Servers,CN=<Site>,CN=Sites,<config>
    $servers = @(Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase "CN=Sites,$config" -Filter '(objectClass=server)' -Properties 'distinguishedName', 'dNSHostName', 'serverReference')
    $ntds = @(Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase "CN=Sites,$config" -Filter '(objectClass=nTDSDSA)' -Properties 'distinguishedName', 'options')
    $gcByServer = @{}
    foreach ($n in $ntds) {
        $opt = 0; if ($null -ne $n.options) { $opt = [int]$n.options }
        $gcByServer[(Get-ADAuditParentDN ([string]$n.distinguishedName))] = (($opt -band 1) -ne 0)
    }
    $serverByComputer = @{}
    foreach ($s in $servers) {
        if ($s.serverReference) { $serverByComputer[[string]$s.serverReference] = $s }
    }

    # FSMO role owners (values are NTDS Settings DNs)
    $roles = @{}
    $roleSources = @(
        @{ Role = 'PDC'; Base = $nc },
        @{ Role = 'RID'; Base = "CN=RID Manager`$,CN=System,$nc" },
        @{ Role = 'Infrastructure'; Base = "CN=Infrastructure,$nc" },
        @{ Role = 'Schema'; Base = "CN=Schema,$config" },
        @{ Role = 'DomainNaming'; Base = "CN=Partitions,$config" }
    )
    foreach ($r in $roleSources) {
        try {
            $o = Invoke-ADAuditLdapQuery -Server $Server -Credential $Credential -SearchBase $r.Base -Scope Base -Filter '(objectClass=*)' -Properties 'fSMORoleOwner' | Select-Object -First 1
            $owner = [string]$o.fSMORoleOwner
            if ($owner) {
                $serverDn = Get-ADAuditParentDN $owner
                if (-not $roles.ContainsKey($serverDn)) { $roles[$serverDn] = New-Object System.Collections.Generic.List[string] }
                $roles[$serverDn].Add($r.Role)
                if ($owner -match '\\0ADEL:|CN=Deleted Objects') {
                    New-ADAuditResult -Scanner 'DomainControllers' -Target $r.Role -Severity 'High' -Finding "FSMO role $($r.Role) is held by a deleted DC ($owner)" -Data ([ordered]@{ Check = 'FSMO' })
                }
            }
        }
        catch { New-ADAuditResult -Scanner 'DomainControllers' -Target $r.Role -Severity 'Info' -Finding "Could not read FSMO owner: $($_.Exception.Message)" -Data ([ordered]@{ Check = 'FSMO' }) }
    }

    $dcs = @($Computers | Where-Object { $_.IsDomainController })
    $now = [DateTime]::UtcNow
    $writable = 0
    $seenServers = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($dc in $dcs) {
        $srv = $serverByComputer[$dc.DistinguishedName]
        $site = $null; $isGc = $null; $dcRoles = @()
        if ($srv) {
            $srvDn = [string]$srv.distinguishedName
            [void]$seenServers.Add($srvDn)
            if ($srvDn -match '^CN=[^,]+,CN=Servers,CN=([^,]+),CN=Sites,') { $site = $Matches[1] }
            $isGc = $gcByServer[$srvDn]
            if ($roles.ContainsKey($srvDn)) { $dcRoles = @($roles[$srvDn]) }
        }
        $isRodc = [bool]$dc.IsReadOnly
        if (-not $isRodc) { $writable++ }

        $ips = $null
        try { $ips = (@([System.Net.Dns]::GetHostAddresses($dc.DnsHostName) | ForEach-Object { $_.IPAddressToString }) -join ', ') } catch { $ips = '(DNS lookup failed)' }

        $issues = @(); $sev = @()
        if (-not $dc.LastLogonUtc -or ($now - $dc.LastLogonUtc).TotalDays -gt $DcStaleDays) {
            $issues += $(if ($dc.LastLogonUtc) { "DC account not seen for $([int]($now - $dc.LastLogonUtc).TotalDays) days (decommissioned without metadata cleanup?)" } else { 'DC account has never logged on' })
            $sev += 'Medium'
        }
        if (-not $srv) { $issues += 'No site server object found for this DC'; $sev += 'Low' }

        New-ADAuditResult -Scanner 'DomainControllers' -Target $dc.Name -Severity (Get-ADAuditMaxSeverity $sev) -Finding ($issues -join '; ') -Data ([ordered]@{
            Check           = 'Inventory'
            DnsHostName     = $dc.DnsHostName
            Site            = $site
            IPAddresses     = $ips
            OperatingSystem = $dc.OperatingSystem
            OSVersion       = $dc.OSVersion
            IsReadOnly      = $isRodc
            IsGlobalCatalog = $isGc
            FsmoRoles       = ($dcRoles -join ', ')
            LastLogonUtc    = $dc.LastLogonUtc
            IssueSeverity = (@($sev) -join ';')
        })
    }

    if ($dcs.Count -gt 0 -and $writable -lt 2) {
        New-ADAuditResult -Scanner 'DomainControllers' -Target $domain -Severity 'Medium' -Finding "Only $writable writable DC in the domain (no redundancy)" -Data ([ordered]@{ Check = 'Redundancy' })
    }

    # Server objects whose DC belongs to this domain but no enabled DC computer matches
    $dcDns = @{}
    foreach ($dc in $dcs) { $dcDns[$dc.DnsHostName.ToLowerInvariant()] = $true }
    foreach ($s in $servers) {
        $sdn = [string]$s.distinguishedName
        if ($seenServers.Contains($sdn)) { continue }
        $h = [string]$s.dNSHostName
        if (-not $h -or -not $h.ToLowerInvariant().EndsWith(".$($domain.ToLowerInvariant())")) { continue }  # other domains in the forest
        if (-not $gcByServer.ContainsKey($sdn)) { continue }  # server without NTDS Settings = not a DC (e.g. leftover from demotion is fine)
        if ($dcDns.ContainsKey($h.ToLowerInvariant())) { continue }
        New-ADAuditResult -Scanner 'DomainControllers' -Target $h -Severity 'Low' -Finding 'NTDS Settings exist but no enabled DC computer account matches (leftover metadata?)' -Data ([ordered]@{ Check = 'Metadata'; DistinguishedName = $sdn })
    }
}
