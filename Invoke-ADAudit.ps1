#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only Active Directory host and configuration scanners (PingCastle-style).

.DESCRIPTION
    Runs any combination of these scanners and writes one CSV per scanner,
    AllFindings.csv (one row per issue, with category and remediation),
    results.json and Summary.html (risk scores, changes, findings) to the output folder.
    With -Baseline it also writes Changes.csv: what changed since a previous run.

      AD-only (LDAP reads, nothing sent to hosts):
        DomainPolicy   - password/lockout policy, MachineAccountQuota, krbtgt age, Guest, Pre-Win2000 access
        Accounts       - privileged & service accounts, password never expires, never logged on,
                         stale, Kerberoast / AS-REP, delegation, too many groups, SID history, adminCount
        Groups         - Domain Admins & other privileged groups (direct + nested members),
                         deep / circular group nesting
        OSInventory    - unsupported / soon-unsupported Windows versions, stale accounts
        LapsBitLocker  - LAPS (legacy + Windows LAPS) coverage, BitLocker key escrow
        DomainControllers - DC inventory: site, IPs, OS, RODC/GC, FSMO roles, redundancy
        AuditPolicy    - audit policy applied to DCs by GPO (read from SYSVOL), missing subcategories
        Permissions    - DCSync rights, dangerous ACEs / owners on Tier-0 objects, GPO edit rights
                         (AD + SYSVOL), LAPS and gMSA password readers

      Per-DC (read-only Security log query over RPC):
        Events         - account / group / SID history / DSRM / delegation / ACL changes in the
                         last -EventDays days, and how far back the Security log actually goes

      Per-host (read-only network queries over TCP 445):
        Spooler        - Print Spooler pipe reachable (critical on DCs)
        Smb            - SMBv1 enabled, SMB signing required, highest SMB2/3 dialect
        LocalAdmin     - members of BUILTIN\Administrators
        Share          - shares, and which share roots the scanning account can list

    Nothing is written to AD or to scanned hosts. LDAP auth can use -Credential;
    per-host scanners always use the current Windows logon (use runas /netonly
    to scan as a different domain account).

.EXAMPLE
    .\Invoke-ADAudit.ps1
    All scanners, all enabled computers seen in the last 90 days, current domain.

.EXAMPLE
    .\Invoke-ADAudit.ps1 -Scanners OSInventory,LapsBitLocker
    AD-only scan; no traffic to member hosts.

.EXAMPLE
    .\Invoke-ADAudit.ps1 -Scanners Smb,Spooler -DomainControllersOnly
    Check only DCs for SMB and Spooler issues.

.EXAMPLE
    .\Invoke-ADAudit.ps1 -Baseline .\ADAudit-20261101-090000
    Full run, plus Changes.csv / a "Changes since baseline" section comparing against an earlier run.

.EXAMPLE
    .\Invoke-ADAudit.ps1 -Scanners Events,AuditPolicy -EventDays 30
    Review the last 30 days of account and group changes on every DC.

.EXAMPLE
    .\Invoke-ADAudit.ps1 -ComputerName srv01.corp.local,srv02.corp.local -Scanners Share,LocalAdmin
#>
[CmdletBinding()]
param(
    [ValidateSet('DomainPolicy', 'Accounts', 'Groups', 'OSInventory', 'LapsBitLocker', 'DomainControllers', 'AuditPolicy', 'Permissions', 'Events', 'Spooler', 'Smb', 'LocalAdmin', 'Share')]
    [string[]]$Scanners = @('DomainPolicy', 'Accounts', 'Groups', 'OSInventory', 'LapsBitLocker', 'DomainControllers', 'AuditPolicy', 'Permissions', 'Events', 'Spooler', 'Smb', 'LocalAdmin', 'Share'),

    [string]$Server,
    [string]$SearchBase,
    [pscredential]$Credential,

    # Limit per-host scanners to these hosts (names or FQDNs)
    [string[]]$ComputerName,
    [switch]$DomainControllersOnly,

    [int]$ActiveDays = 90,
    [int]$PasswordAgeDays = 365,
    [int]$MaxGroupMemberships = 20,
    [int]$MaxNestingDepth = 3,
    [int]$MaxDomainAdmins = 5,
    # Permissions: don't read GPO folder ACLs in SYSVOL
    [switch]$SkipSysvol,
    [string]$ServiceAccountPattern = '^(svc|srv|sa|sql|app|service)[-_.]|[-_.](svc|service|sa)$|^svc',
    [ValidateRange(1, 128)][int]$Throttle = 16,
    [ValidateRange(5, 3600)][int]$TimeoutSeconds = 120,
    [ValidateRange(250, 60000)][int]$NetworkTimeoutMs = 3000,
    [switch]$SkipSmb1,

    # Events scanner
    [ValidateRange(1, 365)][int]$EventDays = 7,
    [ValidateRange(100, 1000000)][int]$EventMaxPerDC = 5000,

    # Previous run folder (or its results.json) to compare against
    [string]$Baseline,

    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath ("ADAudit-" + (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'lib\Common.ps1')
. (Join-Path $here 'lib\Native.ps1')
. (Join-Path $here 'lib\Acl.ps1')
. (Join-Path $here 'lib\Compare.ps1')
. (Join-Path $here 'lib\Remediation.ps1')
Get-ChildItem -Path (Join-Path $here 'Scanners') -Filter '*.ps1' | ForEach-Object { . $_.FullName }

$adScanners = @($Scanners | Where-Object { $_ -in 'DomainPolicy', 'Accounts', 'Groups', 'OSInventory', 'LapsBitLocker', 'DomainControllers', 'AuditPolicy', 'Permissions' })
$hostScanners = @($Scanners | Where-Object { $_ -in 'Spooler', 'Smb', 'LocalAdmin', 'Share' })
$results = New-Object System.Collections.ArrayList
$started = Get-Date

# Load the baseline first so a bad path fails before a long scan
$baselineRun = $null
if ($Baseline) {
    $baselineRun = Read-ADAuditRun -Path $Baseline
    Write-Host ("[+] Baseline: {0} ({1} results)" -f $baselineRun.Meta.Generated, @($baselineRun.Results).Count)
}

# ---------- AD inventory ----------
$allComputers = @()
try {
    Write-Host "[*] Reading computer accounts from AD..."
    $allComputers = @(Get-ADAuditComputer -Server $Server -SearchBase $SearchBase -Credential $Credential -ActiveDays $ActiveDays -IncludeStale)
    Write-Host ("[+] {0} enabled computer accounts ({1} active in last {2} days, {3} DCs)" -f $allComputers.Count, @($allComputers | Where-Object { -not $_.IsStale }).Count, $ActiveDays, @($allComputers | Where-Object { $_.IsDomainController }).Count)
}
catch {
    if ($adScanners.Count -gt 0 -or -not $ComputerName) { throw "AD query failed: $($_.Exception.Message)" }
    Write-Warning "AD query failed ($($_.Exception.Message)); continuing with -ComputerName only and treating targets as non-DCs."
}

$adScope = $allComputers
if ($DomainControllersOnly) { $adScope = @($allComputers | Where-Object { $_.IsDomainController }) }

$groupInventory = $null; $privileged = $null
if (@($Scanners | Where-Object { $_ -in 'Accounts', 'Groups', 'Events', 'Permissions', 'DomainPolicy' }).Count -gt 0) {
    Write-Host "[*] Resolving privileged group membership (direct + nested)..."
    $groupInventory = @(Get-ADAuditGroupInventory -Server $Server -SearchBase $SearchBase -Credential $Credential)
    $privileged = Get-ADAuditPrivilegedMembership -Groups $groupInventory -Server $Server -SearchBase $SearchBase -Credential $Credential
    Write-Host ("[+] {0} groups, {1} privileged groups, {2} distinct privileged principals" -f $groupInventory.Count, @($privileged.Groups).Count, $privileged.MapByMember.Count)
}

foreach ($s in $adScanners) {
    Write-Host "[*] Running $s..."
    try {
        $out = switch ($s) {
            'DomainPolicy' { Invoke-ADAuditDomainPolicyScan -Server $Server -Credential $Credential -Privileged $privileged }
            'Accounts' { Invoke-ADAuditAccountScan -Privileged $privileged -Server $Server -SearchBase $SearchBase -Credential $Credential -ActiveDays $ActiveDays -PasswordAgeDays $PasswordAgeDays -MaxGroupMemberships $MaxGroupMemberships -ServiceAccountPattern $ServiceAccountPattern }
            'Groups' { Invoke-ADAuditGroupScan -Groups $groupInventory -Privileged $privileged -MaxNestingDepth $MaxNestingDepth -MaxDomainAdmins $MaxDomainAdmins -Server $Server -SearchBase $SearchBase -Credential $Credential }
            'OSInventory' { Invoke-ADAuditOSInventory -Computers $adScope }
            'LapsBitLocker' { Invoke-ADAuditLapsBitLocker -Computers $adScope -Server $Server -SearchBase $SearchBase -Credential $Credential }
            'DomainControllers' { Invoke-ADAuditDomainControllerScan -Computers $allComputers -Server $Server -Credential $Credential }
            'AuditPolicy' { Invoke-ADAuditAuditPolicyScan -Server $Server -Credential $Credential }
            'Permissions' { Invoke-ADAuditPermissionScan -Privileged $privileged -Server $Server -Credential $Credential -SkipSysvol:$SkipSysvol }
        }
        foreach ($o in $out) { [void]$results.Add($o) }
    }
    catch { [void]$results.Add((New-ADAuditResult -Scanner $s -Computer '(domain)' -Severity 'Error' -Finding $_.Exception.Message)) }
}

# ---------- DC Security log ----------
if ($Scanners -contains 'Events') {
    $dcTargets = @($allComputers | Where-Object { $_.IsDomainController -and -not $_.IsStale })
    if ($ComputerName) { $dcTargets = @($dcTargets | Where-Object { $ComputerName -contains $_.Name -or $ComputerName -contains $_.DnsHostName }) }
    $privSids = @{}; $privNames = @{}
    if ($privileged) {
        foreach ($g in $privileged.Groups) { if ($g.Sid) { $privSids[$g.Sid] = $g.Label } }
        foreach ($m in $privileged.Members) { if ($m.MemberName) { $privNames[$m.MemberName] = $true } }
    }
    $domainDn = $null
    try { $domainDn = Get-ADAuditDefaultNamingContext -Server $Server -Credential $Credential } catch { }
    Write-Host ("[*] Reading Security logs on {0} DCs (last {1} days)..." -f $dcTargets.Count, $EventDays)
    foreach ($dc in $dcTargets) {
        try {
            foreach ($o in (Invoke-ADAuditEventScan -ComputerName $dc.DnsHostName -EventDays $EventDays -MaxEvents $EventMaxPerDC -PrivilegedSids $privSids -PrivilegedNames $privNames -DomainDN $domainDn -TimeoutMs $NetworkTimeoutMs)) { [void]$results.Add($o) }
        }
        catch { [void]$results.Add((New-ADAuditResult -Scanner 'Events' -Target $dc.DnsHostName -Severity 'Error' -Finding $_.Exception.Message)) }
    }
}

# ---------- Per-host scanners ----------
function Invoke-ADAuditHostScan {
    param([string]$ComputerName, [bool]$IsDomainController, [string[]]$Scanners, [int]$TimeoutMs, [bool]$SkipSmb1)
    if (-not (Test-ADAuditTcpPort -ComputerName $ComputerName -Port 445 -TimeoutMs $TimeoutMs)) {
        New-ADAuditResult -Scanner 'Reachability' -Computer $ComputerName -Severity 'Info' -Finding 'TCP 445 not reachable; host scanners skipped'
        return
    }
    foreach ($s in $Scanners) {
        try {
            switch ($s) {
                'Spooler' { Invoke-ADAuditSpoolerScan -ComputerName $ComputerName -IsDomainController $IsDomainController }
                'Smb' { Invoke-ADAuditSmbScan -ComputerName $ComputerName -IsDomainController $IsDomainController -TimeoutMs $TimeoutMs -SkipSmb1:$SkipSmb1 }
                'LocalAdmin' { Invoke-ADAuditLocalAdminScan -ComputerName $ComputerName }
                'Share' { Invoke-ADAuditShareScan -ComputerName $ComputerName -IsDomainController $IsDomainController }
            }
        }
        catch { New-ADAuditResult -Scanner $s -Computer $ComputerName -Severity 'Error' -Finding $_.Exception.Message }
    }
}

if ($hostScanners.Count -gt 0) {
    if ($ComputerName) {
        $targets = foreach ($n in $ComputerName) {
            $match = $allComputers | Where-Object { $_.Name -ieq $n -or $_.DnsHostName -ieq $n } | Select-Object -First 1
            if ($match) { $match } else { [pscustomobject]@{ Name = $n; DnsHostName = $n; IsDomainController = $false } }
        }
    }
    else { $targets = $allComputers | Where-Object { -not $_.IsStale } }
    if ($DomainControllersOnly) { $targets = $targets | Where-Object { $_.IsDomainController } }
    $targets = @($targets)

    Write-Host ("[*] Running host scanners ({0}) on {1} hosts, {2} at a time..." -f ($hostScanners -join ', '), $targets.Count, $Throttle)

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($f in (Get-ChildItem function: | Where-Object { $_.Name -like '*-ADAudit*' })) {
        $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $f.Name, $f.Definition))
    }
    # Extra headroom so a hung/stopped job can't starve the pool
    $pool = [runspacefactory]::CreateRunspacePool(1, $Throttle * 2, $iss, $Host)
    $pool.Open()

    $queue = New-Object System.Collections.Queue
    foreach ($t in $targets) { $queue.Enqueue($t) }
    $active = New-Object System.Collections.ArrayList
    $done = 0; $total = $targets.Count

    try {
        while ($queue.Count -gt 0 -or $active.Count -gt 0) {
            while ($queue.Count -gt 0 -and $active.Count -lt $Throttle) {
                $t = $queue.Dequeue()
                $ps = [powershell]::Create()
                $ps.RunspacePool = $pool
                [void]$ps.AddCommand('Invoke-ADAuditHostScan').
                    AddParameter('ComputerName', $t.DnsHostName).
                    AddParameter('IsDomainController', [bool]$t.IsDomainController).
                    AddParameter('Scanners', $hostScanners).
                    AddParameter('TimeoutMs', $NetworkTimeoutMs).
                    AddParameter('SkipSmb1', [bool]$SkipSmb1)
                [void]$active.Add([pscustomobject]@{ Target = $t; PS = $ps; Handle = $ps.BeginInvoke(); Started = [DateTime]::UtcNow })
            }

            foreach ($j in @($active)) {
                if ($j.Handle.IsCompleted) {
                    try {
                        foreach ($o in $j.PS.EndInvoke($j.Handle)) { [void]$results.Add($o) }
                        foreach ($e in $j.PS.Streams.Error) {
                            [void]$results.Add((New-ADAuditResult -Scanner 'Runner' -Computer $j.Target.DnsHostName -Severity 'Error' -Finding $e.ToString()))
                        }
                    }
                    catch { [void]$results.Add((New-ADAuditResult -Scanner 'Runner' -Computer $j.Target.DnsHostName -Severity 'Error' -Finding $_.Exception.Message)) }
                    finally { $j.PS.Dispose() }
                    $active.Remove($j); $done++
                }
                elseif (([DateTime]::UtcNow - $j.Started).TotalSeconds -gt $TimeoutSeconds) {
                    [void]$j.PS.BeginStop($null, $null)
                    [void]$results.Add((New-ADAuditResult -Scanner 'Runner' -Computer $j.Target.DnsHostName -Severity 'Error' -Finding "Timed out after $TimeoutSeconds s"))
                    $active.Remove($j); $done++
                }
            }

            if ($total -gt 0) {
                Write-Progress -Activity 'AD audit host scanners' -Status "$done / $total hosts" -PercentComplete ([int](100 * $done / $total))
            }
            Start-Sleep -Milliseconds 200
        }
    }
    finally {
        Write-Progress -Activity 'AD audit host scanners' -Completed
        $pool.Close()
        $pool.Dispose()
    }
}

# ---------- Output ----------
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

function ConvertTo-ADAuditFlatRow {
    param([object[]]$Rows)
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($r in $Rows) { foreach ($p in $r.PSObject.Properties.Name) { if (-not $cols.Contains($p)) { $cols.Add($p) } } }
    foreach ($r in $Rows) {
        $o = [ordered]@{}
        foreach ($c in $cols) {
            $v = $r.$c
            if ($v -is [array]) { $v = ($v -join '; ') }
            elseif ($v -is [DateTime]) { $v = $v.ToString('yyyy-MM-dd HH:mm:ss') }
            $o[$c] = $v
        }
        [pscustomobject]$o
    }
}

$all = @($results)
$flat = New-Object System.Collections.ArrayList
foreach ($g in ($all | Group-Object Scanner)) {
    $rows = @(ConvertTo-ADAuditFlatRow -Rows $g.Group)
    $rows | Export-Csv -Path (Join-Path $OutputPath "$($g.Name).csv") -NoTypeInformation -Encoding UTF8
    foreach ($r in $rows) { [void]$flat.Add($r) }
}

$sevOrder = 'High', 'Medium', 'Low', 'Info', 'Error', 'OK'
$findings = @(Get-ADAuditEnrichedFinding -Rows @($flat) | Sort-Object @{ Expression = { $sevOrder.IndexOf([string]$_.Severity) } }, Category, Rule, Target)
$findings | Export-Csv -Path (Join-Path $OutputPath 'AllFindings.csv') -NoTypeInformation -Encoding UTF8
$score = Get-ADAuditScore -Findings $findings

# results.json (machine-readable; also the input for a later -Baseline)
$domainName = $null
try { $domainName = ConvertTo-ADAuditDnsName (Get-ADAuditDefaultNamingContext -Server $Server -Credential $Credential) } catch { }
$meta = [ordered]@{
    Tool        = 'dtecht-AD'
    Version     = '1.1.0'
    Generated   = $started.ToString('yyyy-MM-ddTHH:mm:sszzz')
    DurationSec = [int]((Get-Date) - $started).TotalSeconds
    Domain      = $domainName
    RunAs       = "$env:USERDOMAIN\$env:USERNAME"
    Host        = $env:COMPUTERNAME
    Scanners    = @($Scanners)
    Score       = [ordered]@{ Overall = $score.Overall; Categories = @($score.Categories) }
    Parameters  = [ordered]@{ ActiveDays = $ActiveDays; PasswordAgeDays = $PasswordAgeDays; MaxGroupMemberships = $MaxGroupMemberships; MaxNestingDepth = $MaxNestingDepth; EventDays = $EventDays; DomainControllersOnly = [bool]$DomainControllersOnly; ComputerName = @($ComputerName) }
}
[ordered]@{ Meta = $meta; Results = @($flat) } | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $OutputPath 'results.json') -Encoding UTF8

# Changes since baseline
$changes = @()
if ($baselineRun) {
    $changes = @(Compare-ADAuditRun -Previous @($baselineRun.Results) -Current @($flat) -PreviousScanners @($baselineRun.Meta.Scanners) -CurrentScanners $Scanners)
    $changes | Export-Csv -Path (Join-Path $OutputPath 'Changes.csv') -NoTypeInformation -Encoding UTF8
}

# Summary HTML
$matrix = foreach ($g in ($all | Group-Object Scanner | Sort-Object Name)) {
    $row = [ordered]@{ Scanner = $g.Name }
    foreach ($s in $sevOrder) { $row[$s] = @($g.Group | Where-Object { $_.Severity -eq $s }).Count }
    [pscustomobject]$row
}
$top = @($findings | Where-Object { $_.Severity -in 'High', 'Medium' -and $_.Scanner -ne 'Events' } | Select-Object Severity, Category, Rule, Target, Finding)
$recent = @($findings | Where-Object { $_.Scanner -eq 'Events' -and $_.Severity -in 'High', 'Medium' } | Select-Object Severity, Target, Finding)

$css = @'
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1b1f24; }
h1 { font-size: 22px; } h2 { font-size: 17px; margin-top: 28px; }
table { border-collapse: collapse; font-size: 13px; }
th, td { border: 1px solid #d0d7de; padding: 4px 10px; text-align: left; }
th { background: #f3f5f7; }
.meta { color: #57606a; font-size: 13px; }
.score { font-size: 34px; font-weight: 600; margin: 4px 0 2px; }
.note { color: #57606a; font-size: 12px; }
</style>
'@
$metaHtml = "<p class='meta'>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') by $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME &middot; Scanners: $($Scanners -join ', ')</p>"
$changesHtml = ''
if ($baselineRun) {
    $chSorted = $changes | Sort-Object @{ Expression = { $sevOrder.IndexOf($_.Severity) } }, Change, Scanner, Target
    $changesHtml = "<h2>Changes since baseline $($baselineRun.Meta.Generated) ($(@($changes).Count))</h2>" +
        $(if ($chSorted) { ($chSorted | ConvertTo-Html -Fragment) } else { '<p>No changes.</p>' })
}
$scoreHtml = "<h2>Risk score</h2><div class='score'>$($score.Overall) / 100</div><p class='note'>Lower is better. Each triggered rule adds High 15 / Medium 8 / Low 3 points to its category (max 100); the overall score is the worst category. Events and Info findings are not scored.</p>" +
    ($score.Categories | ConvertTo-Html -Fragment) +
    "<h2>Rules triggered ($(@($score.Rules).Count))</h2>" +
    $(if ($score.Rules) { ($score.Rules | Select-Object Severity, Category, Rule, Objects, Remediation | ConvertTo-Html -Fragment) } else { '<p>None.</p>' })
$body = "<h1>AD Audit Summary</h1>$metaHtml" + $scoreHtml + $changesHtml +
    "<h2>High and Medium findings ($(@($top).Count))</h2>" +
    $(if ($top) { ($top | ConvertTo-Html -Fragment) } else { '<p>None.</p>' }) +
    $(if ($Scanners -contains 'Events') { "<h2>Recent High/Medium changes on DCs ($(@($recent).Count))</h2>" + $(if ($recent) { ($recent | ConvertTo-Html -Fragment) } else { '<p>None.</p>' }) } else { '' }) +
    "<h2>Results by scanner</h2>" + ($matrix | ConvertTo-Html -Fragment)
ConvertTo-Html -Title 'AD Audit Summary' -Head $css -Body $body | Out-File -FilePath (Join-Path $OutputPath 'Summary.html') -Encoding UTF8

Write-Host ""
$matrix | Format-Table -AutoSize | Out-Host
Write-Host ("[+] Risk score: {0}/100 (lower is better)" -f $score.Overall)
$score.Categories | Format-Table -AutoSize | Out-Host
if ($baselineRun) {
    Write-Host ("[+] Changes since baseline: {0} ({1} New, {2} Resolved, {3} Added to privileged groups, {4} Removed, {5} policy changes)" -f @($changes).Count,
        @($changes | Where-Object Change -eq 'New').Count, @($changes | Where-Object Change -eq 'Resolved').Count,
        @($changes | Where-Object Change -eq 'Added').Count, @($changes | Where-Object Change -eq 'Removed').Count, @($changes | Where-Object Change -eq 'Changed').Count)
}
Write-Host "[+] Results written to $OutputPath"
