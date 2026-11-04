#Requires -Version 5.1
<#
    LapsBitLocker (PingCastle equivalent: laps_bitlocker)
    AD-only. For each enabled computer, checks:
      - Legacy LAPS:  ms-Mcs-AdmPwdExpirationTime
      - Windows LAPS: msLAPS-PasswordExpirationTime
      - BitLocker:    msFVE-RecoveryInformation child objects
    Only expiration timestamps and object existence are read - never passwords
    or recovery keys. Nothing is sent to the computers themselves.

    Permissions note: BitLocker recovery objects are normally visible only to
    Domain Admins (or delegated readers). If none are visible at all, the scanner
    reports BitLocker as 'NotVisible' instead of flagging every computer.
#>

function Invoke-ADAuditLapsBitLocker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Computers,
        [string]$Server,
        [string]$SearchBase,
        [pscredential]$Credential
    )

    $filter = '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $lapsProps = 'distinguishedName', 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime'
    $laps = @{}
    foreach ($r in (Invoke-ADAuditLdapQuery -Server $Server -SearchBase $SearchBase -Credential $Credential -Filter $filter -Properties $lapsProps)) {
        $laps[[string]$r.distinguishedName] = $r
    }

    $bitlocker = @{}
    $blNote = $null
    try {
        foreach ($r in (Invoke-ADAuditLdapQuery -Server $Server -SearchBase $SearchBase -Credential $Credential -Filter '(objectClass=msFVE-RecoveryInformation)' -Properties 'distinguishedName')) {
            # Parent DN = strip the first (unescaped) RDN
            $parent = ([string]$r.distinguishedName) -replace '^(?:[^,\\]|\\.)*,', ''
            $bitlocker[$parent] = 1 + [int]$bitlocker[$parent]
        }
    }
    catch { $blNote = "BitLocker query failed: $($_.Exception.Message)" }
    $blVisible = $bitlocker.Count -gt 0
    if (-not $blVisible -and -not $blNote) { $blNote = 'No recovery objects visible (none escrowed, or no read permission)' }

    $now = [DateTime]::UtcNow
    foreach ($c in $Computers) {
        $row = $laps[$c.DistinguishedName]
        $legacyExp = $null; $winExp = $null
        if ($row) {
            $legacyExp = ConvertFrom-ADAuditFileTime $row.'ms-Mcs-AdmPwdExpirationTime'
            $winExp = ConvertFrom-ADAuditFileTime $row.'msLAPS-PasswordExpirationTime'
        }
        $lapsType = @()
        if ($legacyExp) { $lapsType += 'Legacy' }
        if ($winExp) { $lapsType += 'Windows' }
        $expiry = @($legacyExp, $winExp) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1

        $blCount = [int]$bitlocker[$c.DistinguishedName]
        $blStatus = $(if (-not $blVisible) { 'NotVisible' } elseif ($blCount -gt 0) { 'Escrowed' } else { 'None' })

        $issues = @(); $sev = @()
        if ($c.IsDomainController) {
            $lapsStatus = 'N/A (DC)'
        }
        elseif (-not $lapsType) {
            $lapsStatus = 'None'
            $issues += 'No LAPS-managed local admin password'
            $sev += 'Medium'
        }
        elseif ($expiry -lt $now.AddDays(-7)) {
            $lapsStatus = 'Expired'
            $issues += "LAPS password past expiry since $($expiry.ToString('yyyy-MM-dd')) (not rotating)"
            $sev += 'Low'
        }
        else { $lapsStatus = 'OK' }

        if ($blStatus -eq 'None' -and -not $c.IsStale) {
            $issues += 'No BitLocker recovery key escrowed in AD'
            $sev += 'Low'
        }

        New-ADAuditResult -Scanner 'LapsBitLocker' -Computer $c.Name -Severity (Get-ADAuditMaxSeverity $sev) -Finding ($issues -join '; ') -Data ([ordered]@{
            DnsHostName          = $c.DnsHostName
            IsDomainController   = $c.IsDomainController
            OperatingSystem      = $c.OperatingSystem
            LapsStatus           = $lapsStatus
            LapsType             = ($lapsType -join '+')
            LapsExpiryUtc        = $expiry
            BitLockerStatus      = $blStatus
            BitLockerRecoveryObj = $(if ($blVisible) { $blCount } else { $null })
            IsStale              = $c.IsStale
            Note                 = $(if (-not $blVisible) { $blNote } else { $null })
            IssueSeverity = (@($sev) -join ';')
        })
    }
}
