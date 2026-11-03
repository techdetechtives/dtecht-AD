#Requires -Version 5.1
<#
    Spooler (PingCastle equivalent: spooler)
    Checks whether the Print Spooler named pipe (\\host\pipe\spoolss) is reachable.
    This only asks for the pipe's attributes over SMB; it makes no RPC calls to the
    spooler and does not trigger any authentication coercion.

    Spooler on a DC enables "printer bug" coercion and PrintNightmare-class issues.
#>

function Invoke-ADAuditSpoolerScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName, [bool]$IsDomainController)

    $exposed = $false
    try { $exposed = [bool](Test-Path -LiteralPath "\\$ComputerName\pipe\spoolss" -ErrorAction Stop) }
    catch { $exposed = $false }

    if ($exposed -and $IsDomainController) { $sev = 'High'; $finding = 'Print Spooler reachable on a domain controller (coercion / PrintNightmare risk)' }
    elseif ($exposed) { $sev = 'Info'; $finding = 'Print Spooler reachable' }
    else { $sev = 'OK'; $finding = '' }

    New-ADAuditResult -Scanner 'Spooler' -Computer $ComputerName -Severity $sev -Finding $finding -Data ([ordered]@{
        IsDomainController = $IsDomainController
        SpoolerPipeOpen    = $exposed
    })
}
