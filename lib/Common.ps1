#Requires -Version 5.1
<#
    Shared helpers for the AD audit scanners.
    Everything here is read-only: LDAP searches, TCP connect checks, and result shaping.
#>

function Join-ADAuditLdapPath {
    param([string]$Server, [string]$DistinguishedName)
    $path = 'LDAP://'
    if ($Server) { $path += $Server }
    if ($Server -and $DistinguishedName) { $path += '/' }
    if ($DistinguishedName) { $path += $DistinguishedName }
    return $path
}

function New-ADAuditDirectoryEntry {
    param([Parameter(Mandatory)][string]$Path, [pscredential]$Credential)
    if ($Credential) {
        return New-Object System.DirectoryServices.DirectoryEntry($Path, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    }
    return New-Object System.DirectoryServices.DirectoryEntry($Path)
}

function Get-ADAuditDefaultNamingContext {
    param([string]$Server, [pscredential]$Credential)
    $rootDse = New-ADAuditDirectoryEntry -Path (Join-ADAuditLdapPath -Server $Server -DistinguishedName 'RootDSE') -Credential $Credential
    try {
        $nc = [string]$rootDse.Properties['defaultNamingContext'].Value
        if (-not $nc) { throw "Could not read defaultNamingContext from RootDSE. Is this machine domain-joined, or did you pass -Server?" }
        return $nc
    }
    finally { $rootDse.Dispose() }
}

function Get-ADAuditRootDse {
    param([string]$Server, [pscredential]$Credential)
    $rootDse = New-ADAuditDirectoryEntry -Path (Join-ADAuditLdapPath -Server $Server -DistinguishedName 'RootDSE') -Credential $Credential
    try {
        [pscustomobject]@{
            DefaultNamingContext       = [string]$rootDse.Properties['defaultNamingContext'].Value
            ConfigurationNamingContext = [string]$rootDse.Properties['configurationNamingContext'].Value
            RootDomainNamingContext    = [string]$rootDse.Properties['rootDomainNamingContext'].Value
            DnsHostName                = [string]$rootDse.Properties['dnsHostName'].Value
        }
    }
    finally { $rootDse.Dispose() }
}

function Get-ADAuditParentDN {
    # Strip the first (unescaped) RDN
    param([string]$DistinguishedName)
    return ($DistinguishedName -replace '^(?:[^,\\]|\\.)*,', '')
}

function Invoke-ADAuditLdapQuery {
    <#
        Paged LDAP search. Returns one PSCustomObject per entry with the requested
        properties (single values as scalars, multi-values as arrays, missing as $null).
    #>
    [CmdletBinding()]
    param(
        [string]$Server,
        [string]$SearchBase,
        [Parameter(Mandatory)][string]$Filter,
        [string[]]$Properties = @('distinguishedName'),
        [pscredential]$Credential,
        [ValidateSet('Base', 'OneLevel', 'Subtree')][string]$Scope = 'Subtree'
    )
    if (-not $SearchBase) { $SearchBase = Get-ADAuditDefaultNamingContext -Server $Server -Credential $Credential }

    $root = New-ADAuditDirectoryEntry -Path (Join-ADAuditLdapPath -Server $Server -DistinguishedName $SearchBase) -Credential $Credential
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root, $Filter)
    $searcher.PageSize = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]$Scope
    $searcher.PropertiesToLoad.Clear()
    foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }

    $results = $searcher.FindAll()
    try {
        foreach ($r in $results) {
            $o = [ordered]@{}
            foreach ($p in $Properties) {
                $key = $p.ToLowerInvariant()
                if ($r.Properties.Contains($key)) {
                    $vals = $r.Properties[$key]
                    if ($vals.Count -eq 1) { $o[$p] = $vals[0] } else { $o[$p] = @($vals) }
                }
                else { $o[$p] = $null }
            }
            [pscustomobject]$o
        }
    }
    finally {
        $results.Dispose()
        $searcher.Dispose()
        $root.Dispose()
    }
}

function ConvertFrom-ADAuditFileTime {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { $ft = [Int64]"$Value" } catch { return $null }
    if ($ft -le 0 -or $ft -eq [Int64]::MaxValue) { return $null }
    try { return [DateTime]::FromFileTimeUtc($ft) } catch { return $null }
}

function Get-ADAuditComputer {
    <#
        Enabled computer accounts from AD. By default only computers that logged on
        within -ActiveDays (lastLogonTimestamp) are returned; -IncludeStale returns all.
    #>
    [CmdletBinding()]
    param(
        [string]$Server,
        [string]$SearchBase,
        [pscredential]$Credential,
        [int]$ActiveDays = 90,
        [switch]$IncludeStale
    )
    $filter = '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $props = 'name', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp', 'userAccountControl', 'distinguishedName', 'whenCreated'
    $cutoff = [DateTime]::UtcNow.AddDays(-$ActiveDays)

    foreach ($c in (Invoke-ADAuditLdapQuery -Server $Server -SearchBase $SearchBase -Credential $Credential -Filter $filter -Properties $props)) {
        $last = ConvertFrom-ADAuditFileTime $c.lastLogonTimestamp
        $isStale = (-not $last) -or ($last -lt $cutoff)
        if ($isStale -and -not $IncludeStale) { continue }
        $uac = 0
        if ($null -ne $c.userAccountControl) { $uac = [int]$c.userAccountControl }
        [pscustomobject]@{
            Name               = [string]$c.name
            DnsHostName        = $(if ($c.dNSHostName) { [string]$c.dNSHostName } else { [string]$c.name })
            OperatingSystem    = [string]$c.operatingSystem
            OSVersion          = [string]$c.operatingSystemVersion
            LastLogonUtc       = $last
            IsStale            = $isStale
            IsDomainController = (($uac -band 0x2000) -ne 0) -or (($uac -band 0x4000000) -ne 0)   # SERVER_TRUST_ACCOUNT or RODC
            IsReadOnly         = (($uac -band 0x4000000) -ne 0)                                    # PARTIAL_SECRETS_ACCOUNT
            DistinguishedName  = [string]$c.distinguishedName
            WhenCreated        = $c.whenCreated
        }
    }
}

function Test-ADAuditTcpPort {
    param([Parameter(Mandatory)][string]$ComputerName, [int]$Port = 445, [int]$TimeoutMs = 2000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $client.EndConnect($ar)
        return $true
    }
    catch { return $false }
    finally { $client.Close() }
}

function New-ADAuditResult {
    <#
        Standard result row. Severity: High, Medium, Low, Info, OK, Error.
    #>
    param(
        [Parameter(Mandatory)][string]$Scanner,
        [Parameter(Mandatory)][Alias('Computer')][string]$Target,
        [Parameter(Mandatory)][ValidateSet('High', 'Medium', 'Low', 'Info', 'OK', 'Error')][string]$Severity,
        [string]$Finding,
        [System.Collections.IDictionary]$Data
    )
    $o = [ordered]@{ Scanner = $Scanner; Target = $Target; Severity = $Severity; Finding = $Finding }
    if ($Data) { foreach ($k in $Data.Keys) { $o[$k] = $Data[$k] } }
    [pscustomobject]$o
}

function ConvertTo-ADAuditLdapFilterValue {
    # RFC 4515 escaping for values placed inside an LDAP filter
    param([string]$Value)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ([int]$ch) {
            0x5C { [void]$sb.Append('\5c') }
            0x2A { [void]$sb.Append('\2a') }
            0x28 { [void]$sb.Append('\28') }
            0x29 { [void]$sb.Append('\29') }
            0x00 { [void]$sb.Append('\00') }
            default { [void]$sb.Append($ch) }
        }
    }
    return $sb.ToString()
}

function ConvertTo-ADAuditSidString {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$Value, 0)).Value } catch { return $null }
}

function ConvertTo-ADAuditDnsName {
    param([string]$DistinguishedName)
    return (($DistinguishedName -split ',' | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_.Substring(3) }) -join '.')
}

function Get-ADAuditMaxSeverity {
    param([string[]]$Severity)
    $rank = @{ 'Error' = 5; 'High' = 4; 'Medium' = 3; 'Low' = 2; 'Info' = 1; 'OK' = 0 }
    $best = 'OK'
    foreach ($s in $Severity) { if ($s -and $rank[$s] -gt $rank[$best]) { $best = $s } }
    return $best
}
