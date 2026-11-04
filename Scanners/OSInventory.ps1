#Requires -Version 5.1
<#
    OSInventory (PingCastle equivalent: computerversion)
    AD-only. Reads operatingSystem / operatingSystemVersion / lastLogonTimestamp
    from computer objects and flags unsupported or soon-unsupported Windows builds.
    Nothing is sent to the computers themselves.

    End-of-support dates are a built-in table (as of late 2026). Verify against
    https://learn.microsoft.com/lifecycle before acting, and remember paid ESU
    can extend some products.
#>

function Get-ADAuditOSSupportInfo {
    param([string]$OperatingSystem, [string]$OSVersion)

    $os = "$OperatingSystem"
    $major = $null; $build = $null
    if ($OSVersion -match '^(\d+\.\d+)') { $major = $Matches[1] }
    if ($OSVersion -match '\((\d+)\)') { $build = [int]$Matches[1] }

    $product = $null; $eos = $null

    if (-not $os -or $os -notmatch 'Windows') {
        return [pscustomobject]@{ Product = $(if ($os) { $os } else { '(not recorded)' }); Build = $build; EndOfSupport = $null }
    }

    $isServer = $os -match 'Server'
    $isLtsc = $os -match 'LTS'
    $isEnt = $os -match 'Enterprise|Education'

    if ($isServer) {
        switch ($major) {
            '5.2' { $product = 'Windows Server 2003'; $eos = '2015-07-14' }
            '6.0' { $product = 'Windows Server 2008'; $eos = '2020-01-14' }
            '6.1' { $product = 'Windows Server 2008 R2'; $eos = '2020-01-14' }
            '6.2' { $product = 'Windows Server 2012'; $eos = '2023-10-10' }
            '6.3' { $product = 'Windows Server 2012 R2'; $eos = '2023-10-10' }
            '10.0' {
                switch ($build) {
                    14393 { $product = 'Windows Server 2016'; $eos = '2027-01-12' }
                    17763 { $product = 'Windows Server 2019'; $eos = '2029-01-09' }
                    20348 { $product = 'Windows Server 2022'; $eos = '2031-10-14' }
                    26100 { $product = 'Windows Server 2025'; $eos = '2034-10-10' }
                    default {
                        # Semi-Annual Channel server builds (1709-20H2) are all out of support
                        if ($build -and $build -lt 20348) { $product = "Windows Server SAC build $build"; $eos = '2022-08-09' }
                    }
                }
            }
        }
    }
    else {
        switch ($major) {
            '5.1' { $product = 'Windows XP'; $eos = '2014-04-08' }
            '6.0' { $product = 'Windows Vista'; $eos = '2017-04-11' }
            '6.1' { $product = 'Windows 7'; $eos = '2020-01-14' }
            '6.2' { $product = 'Windows 8'; $eos = '2016-01-12' }
            '6.3' { $product = 'Windows 8.1'; $eos = '2023-01-10' }
            '10.0' {
                if ($build -and $build -lt 22000) {
                    if ($isLtsc) {
                        switch ($build) {
                            10240 { $product = 'Windows 10 LTSB 2015'; $eos = '2025-10-14' }
                            14393 { $product = 'Windows 10 LTSB 2016'; $eos = '2026-10-13' }
                            17763 { $product = 'Windows 10 LTSC 2019'; $eos = '2029-01-09' }
                            19044 { $product = 'Windows 10 LTSC 2021'; $eos = '2027-01-12' }
                        }
                    }
                    if (-not $product) { $product = "Windows 10 (build $build)"; $eos = '2025-10-14' }
                }
                elseif ($build) {
                    if ($isLtsc -and $build -eq 26100) { $product = 'Windows 11 LTSC 2024'; $eos = '2029-10-09' }
                    else {
                        $tbl = @{
                            22000 = @('21H2', '2024-10-08', '2023-10-10')
                            22621 = @('22H2', '2025-10-14', '2024-10-08')
                            22631 = @('23H2', '2026-11-10', '2025-11-11')
                            26100 = @('24H2', '2027-10-12', '2026-10-13')
                            26200 = @('25H2', '2028-10-10', '2027-10-12')
                        }
                        if ($tbl.ContainsKey($build)) {
                            $row = $tbl[$build]
                            $product = "Windows 11 $($row[0]) " + $(if ($isEnt) { '(Ent/Edu)' } else { '(Home/Pro)' })
                            $eos = $(if ($isEnt) { $row[1] } else { $row[2] })
                        }
                        else { $product = "Windows 11 (build $build, not in table)" }
                    }
                }
            }
        }
    }

    if (-not $product) { $product = "$os $OSVersion".Trim() }
    $eosDate = $null
    if ($eos) { $eosDate = [DateTime]::ParseExact($eos, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
    [pscustomobject]@{ Product = $product; Build = $build; EndOfSupport = $eosDate }
}

function Invoke-ADAuditOSInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Computers, [int]$EndingSoonDays = 180)

    $today = (Get-Date).Date
    foreach ($c in $Computers) {
        $info = Get-ADAuditOSSupportInfo -OperatingSystem $c.OperatingSystem -OSVersion $c.OSVersion
        $status = 'Unknown'
        if ($info.EndOfSupport) {
            if ($info.EndOfSupport -lt $today) { $status = 'Unsupported' }
            elseif ($info.EndOfSupport -lt $today.AddDays($EndingSoonDays)) { $status = 'EndingSoon' }
            else { $status = 'Supported' }
        }

        $issues = @(); $sev = @()
        switch ($status) {
            'Unsupported' { $issues += "Out of support since $($info.EndOfSupport.ToString('yyyy-MM-dd'))"; $sev += 'High' }
            'EndingSoon'  { $issues += "Support ends $($info.EndOfSupport.ToString('yyyy-MM-dd'))"; $sev += 'Medium' }
            'Unknown'     { if (-not $c.OperatingSystem) { $issues += 'No OS recorded in AD' ; $sev += 'Info' } else { $issues += 'Support date unknown'; $sev += 'Low' } }
        }
        if ($c.IsStale) { $issues += 'Enabled account not seen recently (stale)'; $sev += 'Low' }

        New-ADAuditResult -Scanner 'OSInventory' -Computer $c.Name -Severity (Get-ADAuditMaxSeverity $sev) -Finding ($issues -join '; ') -Data ([ordered]@{
            DnsHostName        = $c.DnsHostName
            IsDomainController = $c.IsDomainController
            OperatingSystem    = $c.OperatingSystem
            OSVersion          = $c.OSVersion
            Product            = $info.Product
            EndOfSupport       = $(if ($info.EndOfSupport) { $info.EndOfSupport.ToString('yyyy-MM-dd') } else { $null })
            SupportStatus      = $status
            LastLogonUtc       = $c.LastLogonUtc
            IsStale            = $c.IsStale
            IssueSeverity = (@($sev) -join ';')
        })
    }
}
