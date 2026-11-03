#Requires -Version 5.1
<#
    LocalAdmin (PingCastle equivalent: localadmin)
    Lists members of BUILTIN\Administrators (S-1-5-32-544) on each host via
    NetLocalGroupGetMembers - a read-only SAMR query.

    Windows 10 1607+ / Server 2016+ restrict remote SAM enumeration to local admins
    by default (RestrictRemoteSAM), so a non-admin scanning account will mostly get
    'Access denied'. Run as an account with local admin rights for full coverage.
#>

function Invoke-ADAuditLocalAdminScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName)

    $sidUsageNames = @{ 1 = 'User'; 2 = 'Group'; 3 = 'Domain'; 4 = 'Alias'; 5 = 'WellKnownGroup'; 6 = 'DeletedAccount'; 7 = 'Invalid'; 8 = 'Unknown'; 9 = 'Computer' }
    $broadSids = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-7' = 'Anonymous'; 'S-1-5-32-545' = 'BUILTIN\Users'; 'S-1-5-4' = 'Interactive' }
    $broadRids = @{ '513' = 'Domain Users'; '515' = 'Domain Computers'; '514' = 'Domain Guests' }

    $err = 0
    $groupName = [ADAudit.Native]::LookupLocalName($ComputerName, 'S-1-5-32-544', [ref]$err)
    if (-not $groupName) { $groupName = 'Administrators' }

    $err = 0
    $members = [ADAudit.Native]::GetLocalGroupMembers($ComputerName, $groupName, [ref]$err)
    if ($err -ne 0) {
        $msg = switch ($err) {
            5 { 'Access denied (remote SAM enumeration restricted; run as local admin)' }
            53 { 'Network path not found' }
            1722 { 'RPC server unavailable' }
            2220 { "Group '$groupName' not found" }
            default { "NetLocalGroupGetMembers error $err" }
        }
        New-ADAuditResult -Scanner 'LocalAdmin' -Computer $ComputerName -Severity 'Info' -Finding $msg -Data ([ordered]@{
            Member = $null; MemberSid = $null; MemberType = $null; ErrorCode = $err
        })
        return
    }

    foreach ($m in $members) {
        $sid = [string]$m.Sid
        $type = $sidUsageNames[[int]$m.SidUsage]
        $rid = $(if ($sid -match '-(\d+)$') { $Matches[1] } else { $null })
        $sev = 'OK'; $finding = ''

        if ($broadSids.ContainsKey($sid)) {
            $sev = 'High'; $finding = "Broad principal '$($broadSids[$sid])' is a local admin"
        }
        elseif ($sid -match '^S-1-5-21-' -and $rid -and $broadRids.ContainsKey($rid) -and $m.SidUsage -eq 2) {
            $sev = 'High'; $finding = "Broad group '$($broadRids[$rid])' is a local admin"
        }
        elseif ($m.SidUsage -in 6, 7, 8 -or -not $m.Name) {
            $sev = 'Low'; $finding = 'Orphaned / unresolvable SID in local Administrators'
        }
        elseif ($m.SidUsage -eq 1 -and $rid -ne '500') {
            $sev = 'Low'; $finding = 'Individual user account is a local admin'
        }

        New-ADAuditResult -Scanner 'LocalAdmin' -Computer $ComputerName -Severity $sev -Finding $finding -Data ([ordered]@{
            Member = $m.Name; MemberSid = $sid; MemberType = $type; ErrorCode = 0
        })
    }
}
