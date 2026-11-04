#Requires -Version 5.1
<#
.SYNOPSIS
    Static read-only guard for dtecht-AD. Fails (exit 1) if any script could write to
    AD, a DC, a scanned host or the registry.

.DESCRIPTION
    Parses every .ps1 with the PowerShell AST (comments and strings are ignored, so
    remediation text such as 'Set-ADAccountControl ...' is fine) and checks:

      1. Commands      - every command must be on an allowlist of read-only cmdlets or
                         this tool's own functions. Any external program (auditpol, net,
                         dsacls, reg, sc, wevtutil, ...) or unknown cmdlet fails.
                         Local report writers (New-Item, Export-Csv, Out-File) are only
                         allowed in Invoke-ADAudit.ps1.
      2. Methods       - ADSI / registry / WMI / file-write methods (CommitChanges, Put,
                         SetInfo, Invoke, DeleteTree, MoveTo, Rename, SetValue,
                         WriteAllText, SetAccessControl, ...) are denied everywhere.
                         Stream/BinaryWriter.Write is only allowed in Smb.ps1 (it builds and
                         sends the SMB NEGOTIATE packet).
      3. Assignments   - nothing may be assigned to .Properties[...] / .Properties.X
                         (that is how a DirectoryEntry would be modified).
      4. Types         - DirectoryEntry may only be created in lib/Common.ps1; registry,
                         WMI/CIM and ActiveDirectory write-capable classes are denied.
      5. Native APIs   - every DllImport in lib/Native.ps1 must be on the read-only list.
      6. LDAP binds    - New-ADAuditDirectoryEntry must request ReadonlyServer.

    Run:  pwsh -File tests/Test-ReadOnly.ps1      (also runs in GitHub Actions)
#>
[CmdletBinding()]
param([string]$Root = (Split-Path -Parent $PSScriptRoot))

$failures = New-Object System.Collections.Generic.List[string]
function Fail([string]$File, $Extent, [string]$Why) {
    $line = $(if ($Extent) { $Extent.StartLineNumber } else { 0 })
    $failures.Add(('{0}:{1}  {2}' -f $File, $line, $Why))
}

# ---- 1. Command allowlist ----
$readOnlyCommands = @(
    'Where-Object', 'Select-Object', 'Sort-Object', 'Group-Object', 'Measure-Object', 'ForEach-Object',
    'New-Object', 'Add-Member', 'Add-Type', 'Join-Path', 'Split-Path', 'Test-Path', 'Get-Date', 'Get-Location',
    'Get-ChildItem', 'Get-Content', 'Import-Csv', 'Get-Acl', 'Get-WinEvent',
    'ConvertTo-Json', 'ConvertFrom-Json', 'ConvertTo-Html', 'ConvertTo-Csv',
    'Write-Host', 'Write-Progress', 'Write-Warning', 'Write-Verbose', 'Write-Output',
    'Out-Host', 'Out-Null', 'Out-String', 'Format-Table', 'Start-Sleep'
)
$localWriteCommands = @('New-Item', 'Export-Csv', 'Out-File')   # report output only
$localWriteAllowedIn = @('Invoke-ADAudit.ps1')
$toolPrefixes = '-ADAudit'
$testHelpers = @('Fail')

# ---- 2. Denied methods ----
$deniedMethods = @(
    'CommitChanges', 'SetInfo', 'Put', 'PutEx', 'Invoke', 'InvokeSet', 'DeleteTree', 'DeleteObject', 'MoveTo', 'Rename',
    'CopyTo', 'SetPassword', 'ChangePassword', 'SetAccessControl', 'SetSecurityDescriptorSddlForm', 'SetSecurityDescriptorBinaryForm',
    'SetValue', 'CreateSubKey', 'DeleteValue', 'DeleteSubKey', 'DeleteSubKeyTree', 'OpenRemoteBaseKey',
    'WriteAllText', 'WriteAllBytes', 'WriteAllLines', 'AppendAllText', 'AppendAllLines', 'Delete', 'Create', 'CreateDirectory', 'Move', 'Replace',
    'InvokeMethod', 'Send', 'BeginSend', 'SendTo', 'SendAsync', 'UploadString', 'UploadData', 'UploadFile'
)
$writeOnlyIn = @{ 'Write' = @('Smb.ps1') }   # SMB NEGOTIATE packet builder / sender

# ---- 4. Types ----
$deniedTypes = 'Microsoft\.Win32\.Registry|System\.Management\.Management(Class|Object)|CimInstance|DirectoryServices\.ActiveDirectory\.|DirectoryServices\.AccountManagement|System\.Net\.WebClient|System\.Net\.Http'

# ---- 5. Native APIs ----
$allowedNative = @('NetLocalGroupGetMembers', 'NetShareEnum', 'NetApiBufferFree', 'LookupAccountSid')

$files = Get-ChildItem -Path $Root -Recurse -Filter '*.ps1' | Where-Object { $_.FullName -notmatch '[\\/]tests[\\/]' }
$ownFunctions = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$asts = @{}
foreach ($f in $files) {
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
    if ($errs) { Fail $f.Name $errs[0].Extent "Parse error: $($errs[0].Message)" ; continue }
    $asts[$f.FullName] = $ast
    foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { [void]$ownFunctions.Add($fn.Name) }
}

foreach ($f in $files) {
    $ast = $asts[$f.FullName]
    if (-not $ast) { continue }
    $name = $f.Name

    foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $cmd = $c.GetCommandName()
        if (-not $cmd) {
            # '& $x' / '. $x' : allowed only for dot-sourcing this repo's own files
            if ($c.InvocationOperator -eq 'Dot' -or $c.InvocationOperator -eq 'Ampersand') {
                $t = $c.CommandElements[0].Extent.Text
                if ($t -notmatch 'Join-Path \$here|\$_\.FullName') { Fail $name $c.Extent "Dynamic invocation: $t" }
            }
            continue
        }
        if ($readOnlyCommands -contains $cmd -or $ownFunctions.Contains($cmd) -or $cmd -like "*$toolPrefixes*" -or $testHelpers -contains $cmd) { continue }
        if ($localWriteCommands -contains $cmd) {
            if ($localWriteAllowedIn -notcontains $name) { Fail $name $c.Extent "Local write command '$cmd' outside the report stage" }
            continue
        }
        Fail $name $c.Extent "Command not on read-only allowlist: $cmd"
    }

    foreach ($m in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
        $mn = $m.Member.Extent.Text.Trim("'", '"')
        if ($mn -eq 'Create' -and $m.Static -and $m.Expression.Extent.Text -in '[powershell]', '[runspacefactory]') { continue }   # local runspace
        if ($deniedMethods -contains $mn) { Fail $name $m.Extent "Write-capable method: .$mn()" }
        if ($writeOnlyIn.ContainsKey($mn) -and $writeOnlyIn[$mn] -notcontains $name) { Fail $name $m.Extent ".$mn() only allowed in $($writeOnlyIn[$mn] -join ', ')" }
        if ($mn -in 'Add', 'Clear', 'Remove', 'Insert', 'AddRange' -and $m.Expression.Extent.Text -match '\.(Children|Properties)(\[|$|\.)') { Fail $name $m.Extent "Modifies directory entry: $($m.Extent.Text)" }
    }

    foreach ($a in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
        if ($a.Left.Extent.Text -match '\.Properties(\[|\.)') { Fail $name $a.Extent "Assignment to directory entry property: $($a.Left.Extent.Text)" }
        if ($a.Left.Extent.Text -match '\.(Password|UsePropertyCache)\b') { Fail $name $a.Extent "Assignment to $($a.Left.Extent.Text)" }
    }

    $text = $ast.Extent.Text
    foreach ($t in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] -or $n -is [System.Management.Automation.Language.TypeConstraintAst] }, $true)) {
        if ($t.TypeName.FullName -match $deniedTypes) { Fail $name $t.Extent "Write-capable type: $($t.TypeName.FullName)" }
    }
    foreach ($no in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-Object' }, $true)) {
        $typeArg = ($no.CommandElements | Select-Object -Skip 1 | Where-Object { $_ -isnot [System.Management.Automation.Language.CommandParameterAst] } | Select-Object -First 1).Extent.Text
        if ($typeArg -match $deniedTypes) { Fail $name $no.Extent "Write-capable type: $typeArg" }
        if ($typeArg -match 'DirectoryServices\.DirectoryEntry' -and $name -ne 'Common.ps1') { Fail $name $no.Extent 'DirectoryEntry created outside lib/Common.ps1' }
    }

    if ($name -eq 'Native.ps1') {
        foreach ($mm in [regex]::Matches($text, 'static\s+extern\s+\w+\s+(\w+)\s*\(')) {
            if ($allowedNative -notcontains $mm.Groups[1].Value) { Fail $name $null "Native API not on read-only list: $($mm.Groups[1].Value)" }
        }
    }
    elseif ($text -match 'DllImport') { Fail $name $null 'DllImport outside lib/Native.ps1' }

    if ($name -eq 'Common.ps1') {
        if ($text -notmatch "AuthenticationTypes\]'[^']*ReadonlyServer") { Fail $name $null 'LDAP bind does not request ReadonlyServer' }
        if ($text -match 'SecurityMasks\][^\r\n]*Sacl') { Fail $name $null 'SACL read requested (needs SeSecurityPrivilege; not needed)' }
    }
}

if ($failures.Count) {
    Write-Host "READ-ONLY CHECK FAILED ($($failures.Count)):" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  $_" }
    exit 1
}
Write-Host "Read-only check passed: $($files.Count) scripts, $($ownFunctions.Count) functions, no write-capable calls." -ForegroundColor Green
