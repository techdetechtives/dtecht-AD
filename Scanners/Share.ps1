#Requires -Version 5.1
<#
    Share (PingCastle equivalent: share)
    Enumerates shares with NetShareEnum (level 1, read-only) and, for disk shares,
    checks whether the scanning account can LIST the share root. It reads at most
    one directory entry and never opens, writes or changes files or ACLs.

    Tip: run this scanner as a plain domain user. Anything it can list is then
    readable by every domain user, which is what you want to find.
#>

function Invoke-ADAuditShareScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName, [bool]$IsDomainController)

    $expected = @('SYSVOL', 'NETLOGON', 'print$')
    $err = 0
    $shares = [ADAudit.Native]::GetShares($ComputerName, [ref]$err)
    if ($err -ne 0) {
        $msg = switch ($err) { 5 { 'Access denied enumerating shares' } 53 { 'Network path not found' } default { "NetShareEnum error $err" } }
        New-ADAuditResult -Scanner 'Share' -Computer $ComputerName -Severity 'Info' -Finding $msg -Data ([ordered]@{
            Share = $null; ShareType = $null; IsSpecial = $null; Remark = $null; ListableByScanner = $null
        })
        return
    }

    $specialFlag = [uint32]2147483648   # STYPE_SPECIAL (0x80000000)
    foreach ($s in $shares) {
        $base = [uint32]($s.Type -band [uint32]0x0FFFFFFF)
        $isSpecial = ($s.Type -band $specialFlag) -ne 0
        $typeName = switch ($base) { 0 { 'Disk' } 1 { 'Print' } 2 { 'Device' } 3 { 'IPC' } default { "Type$base" } }
        if ($typeName -ne 'Disk') { continue }

        $unc = "\\$ComputerName\$($s.Name)"
        $listable = $false
        try {
            $enum = [System.IO.Directory]::EnumerateFileSystemEntries($unc).GetEnumerator()
            try { [void]$enum.MoveNext() } finally { $enum.Dispose() }
            $listable = $true
        }
        catch { $listable = $false }

        $sev = 'OK'; $finding = ''
        if ($listable) {
            if ($isSpecial) { $sev = 'Info'; $finding = 'Admin share listable (scanning account has admin rights here)' }
            elseif ($expected -contains $s.Name) { $sev = 'OK' }
            else { $sev = 'Medium'; $finding = 'Share root listable by scanning account - review share/NTFS permissions' }
        }

        New-ADAuditResult -Scanner 'Share' -Computer $ComputerName -Severity $sev -Finding $finding -Data ([ordered]@{
            Share = $s.Name; ShareType = $typeName; IsSpecial = $isSpecial; Remark = $s.Remark; ListableByScanner = $listable
        })
    }
}
