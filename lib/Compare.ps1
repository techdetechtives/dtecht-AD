#Requires -Version 5.1
<#
    Run-to-run comparison.
    Every run writes results.json. Passing -Baseline <previous run folder or results.json>
    compares the two runs and reports what changed:

      Added / Removed  - members of privileged groups (direct or nested)
      Changed          - DomainPolicy settings whose value changed
      New / Resolved   - individual findings (one per issue in the Finding text)

    Numbers and dates inside findings are normalised ("Password is 400 days old"
    and "Password is 401 days old" are the same finding). Host-scanner findings
    are only marked Resolved when the host was actually scanned again, so an
    unreachable host doesn't look fixed. The Events scanner is time-windowed and
    is not compared.
#>

$script:ADAuditAdScannerNames = @('DomainPolicy', 'Accounts', 'Groups', 'OSInventory', 'LapsBitLocker', 'AuditPolicy', 'DomainControllers', 'Permissions')
$script:ADAuditNotCompared = @('Events', 'Runner', 'Reachability')

function Read-ADAuditRun {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Container) { $Path = Join-Path $Path 'results.json' }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Baseline not found: $Path" }
    $run = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $run.Results) { throw "Baseline has no Results: $Path" }
    # PowerShell 7 turns ISO timestamps into DateTime; keep one readable format
    if ($run.Meta -and $run.Meta.Generated -is [datetime]) { $run.Meta.Generated = $run.Meta.Generated.ToString('yyyy-MM-dd HH:mm') }
    return $run
}

function ConvertTo-ADAuditIssueKey {
    param([string]$Issue)
    $k = $Issue.Trim()
    $k = $k -replace '\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?', '<date>'
    $k = $k -replace '\d+', '#'
    return $k.ToLowerInvariant()
}

function Split-ADAuditFinding {
    param([string]$Finding)
    if (-not $Finding) { return @() }
    # Split on '; ' that is not inside parentheses
    $parts = @(); $depth = 0; $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Finding.Length; $i++) {
        $c = $Finding[$i]
        if ($c -eq '(') { $depth++ } elseif ($c -eq ')' -and $depth -gt 0) { $depth-- }
        if ($c -eq ';' -and $depth -eq 0 -and $i + 1 -lt $Finding.Length -and $Finding[$i + 1] -eq ' ') {
            $parts += $sb.ToString(); [void]$sb.Clear(); $i++; continue
        }
        [void]$sb.Append($c)
    }
    if ($sb.Length) { $parts += $sb.ToString() }
    return @($parts | Where-Object { $_.Trim() })
}

function New-ADAuditChange {
    param([string]$Change, [string]$Severity, [string]$Scanner, [string]$Target, [string]$Detail, [string]$Previous, [string]$Current)
    [pscustomobject][ordered]@{
        Change = $Change; Severity = $Severity; Scanner = $Scanner; Target = $Target; Detail = $Detail; Previous = $Previous; Current = $Current
    }
}

function Test-ADAuditPrivMemberRow { param($r) return ($r.Scanner -eq 'Groups' -and $r.Check -eq 'PrivilegedMember') }

function Get-ADAuditFindingIndex {
    # key (scanner|target|normalised issue) -> first matching row/issue
    param([object[]]$Rows)
    $h = @{}
    foreach ($r in $Rows) {
        if (($r.Scanner -eq 'DomainPolicy') -or (Test-ADAuditPrivMemberRow $r) -or ($r.Severity -in 'OK', 'Error') -or (-not $r.Finding)) { continue }
        foreach ($i in (Get-ADAuditIssue -Row $r)) {
            if ($i.Severity -in 'OK', 'Error') { continue }
            $key = "$($r.Scanner)|$($r.Target)|$(ConvertTo-ADAuditIssueKey $i.Issue)".ToLowerInvariant()
            if (-not $h.ContainsKey($key)) { $h[$key] = [pscustomobject]@{ Row = $r; Issue = $i.Issue; Severity = $i.Severity } }
        }
    }
    return $h
}

function Compare-ADAuditRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Previous,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Current,
        [string[]]$PreviousScanners,
        [string[]]$CurrentScanners
    )

    # Only compare scanners that ran both times
    $both = @($script:ADAuditAdScannerNames + 'Spooler', 'Smb', 'LocalAdmin', 'Share')
    if ($PreviousScanners) { $both = @($both | Where-Object { $_ -in $PreviousScanners }) }
    if ($CurrentScanners) { $both = @($both | Where-Object { $_ -in $CurrentScanners }) }
    $prev = @($Previous | Where-Object { $_.Scanner -in $both })
    $cur = @($Current | Where-Object { $_.Scanner -in $both })

    # --- Privileged group membership ---
    $pPm = @{}; foreach ($r in $prev) { if (Test-ADAuditPrivMemberRow $r) { $pPm["$($r.Group)|$($r.DistinguishedName)".ToLowerInvariant()] = $r } }
    $cPm = @{}; foreach ($r in $cur) { if (Test-ADAuditPrivMemberRow $r) { $cPm["$($r.Group)|$($r.DistinguishedName)".ToLowerInvariant()] = $r } }
    foreach ($k in $cPm.Keys) {
        if (-not $pPm.ContainsKey($k)) {
            $r = $cPm[$k]
            New-ADAuditChange -Change 'Added' -Severity 'High' -Scanner 'Groups' -Target $r.Member -Detail "Now a member of $($r.Group) ($($r.Membership))" -Current $r.DistinguishedName
        }
    }
    foreach ($k in $pPm.Keys) {
        if (-not $cPm.ContainsKey($k)) {
            $r = $pPm[$k]
            New-ADAuditChange -Change 'Removed' -Severity 'Info' -Scanner 'Groups' -Target $r.Member -Detail "No longer a member of $($r.Group)" -Previous $r.DistinguishedName
        }
    }

    # --- Domain policy values ---
    $pDp = @{}; foreach ($r in $prev) { if ($r.Scanner -eq 'DomainPolicy' -and $r.Setting) { $pDp[[string]$r.Setting] = $r } }
    foreach ($r in $cur) {
        if ($r.Scanner -ne 'DomainPolicy' -or -not $r.Setting) { continue }
        $p = $pDp[[string]$r.Setting]
        if ($p -and ([string]$p.Value -ne [string]$r.Value)) {
            $sev = $(if ($r.Severity -and $r.Severity -ne 'OK') { $r.Severity } else { 'Info' })
            New-ADAuditChange -Change 'Changed' -Severity $sev -Scanner 'DomainPolicy' -Target $r.Setting -Detail "$($r.Setting) changed" -Previous ([string]$p.Value) -Current ([string]$r.Value)
        }
    }

    # --- Individual findings ---
    $pF = Get-ADAuditFindingIndex -Rows $prev
    $cF = Get-ADAuditFindingIndex -Rows $cur

    # Which host-scanner targets were actually scanned this time?
    $scannedNow = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $cur) { [void]$scannedNow.Add("$($r.Scanner)|$($r.Target)") }

    foreach ($k in $cF.Keys) {
        if (-not $pF.ContainsKey($k)) {
            $x = $cF[$k]
            New-ADAuditChange -Change 'New' -Severity $x.Severity -Scanner $x.Row.Scanner -Target $x.Row.Target -Detail $x.Issue
        }
    }
    foreach ($k in $pF.Keys) {
        if ($cF.ContainsKey($k)) { continue }
        $x = $pF[$k]
        $isAd = $x.Row.Scanner -in $script:ADAuditAdScannerNames
        if (-not $isAd -and -not $scannedNow.Contains("$($x.Row.Scanner)|$($x.Row.Target)")) { continue }
        New-ADAuditChange -Change 'Resolved' -Severity 'Info' -Scanner $x.Row.Scanner -Target $x.Row.Target -Detail $x.Issue
    }
}
