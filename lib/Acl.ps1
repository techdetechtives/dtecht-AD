#Requires -Version 5.1
<#
    Security descriptor parsing and ACE evaluation, in plain PowerShell so it
    behaves the same everywhere (no ActiveDirectorySecurity / SecurityIdentifier).

      ConvertFrom-ADAuditSidBytes            binary SID -> 'S-1-5-21-...'
      ConvertFrom-ADAuditSecurityDescriptor  self-relative SD bytes -> owner + DACL ACEs
      Get-ADAuditAceRight                    ACE -> dangerous right names relevant to a target kind
      Test-ADAuditAceInheritsTo              does an ACE on a container reach child objects of a class?
#>

$script:ADAuditGuid = @{
    # Attributes / property sets (WriteProperty object types)
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'WriteMember'                   # member
    '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'AddKeyCredentialLink'          # msDS-KeyCredentialLink
    'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'WriteSPN'                      # servicePrincipalName
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'WriteRBCD'                     # msDS-AllowedToActOnBehalfOfOtherIdentity
    'f30e3bbe-9ff0-11d1-b603-0000f80367c1' = 'WriteGPLink'                   # gPLink
    'f30e3bc1-9ff0-11d1-b603-0000f80367c1' = 'WriteGPCFileSysPath'           # gPCFileSysPath
    'bf9679a8-0de6-11d0-a285-00aa003049e2' = 'WriteScriptPath'               # scriptPath
    'bf967a68-0de6-11d0-a285-00aa003049e2' = 'WriteUAC'                      # userAccountControl
    '00fbf30c-91fe-11d1-aebc-0000f80367c1' = 'WriteAltSecurityIdentities'    # altSecurityIdentities
    '4c164200-20c0-11d0-a768-00aa003049e2' = 'WriteAccountRestrictions'      # property set: UAC, RBCD, ...
}
$script:ADAuditExtendedRight = @{
    '00299570-246d-11d0-a768-00aa006e0529' = 'ForceChangePassword'
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'GetChanges'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'GetChangesAll'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'GetChangesInFilteredSet'
}
$script:ADAuditClassGuid = @{
    computer = 'bf967a86-0de6-11d0-a285-00aa003049e2'
    user     = 'bf967aba-0de6-11d0-a285-00aa003049e2'
    group    = 'bf967a9c-0de6-11d0-a285-00aa003049e2'
}

$script:ADAuditRightsByKind = @{
    Common        = @('GenericAll', 'WriteDacl', 'WriteOwner', 'WriteAllProperties')
    Domain        = @('AllExtendedRights', 'GetChanges', 'GetChangesAll', 'GetChangesInFilteredSet', 'WriteGPLink')
    OU            = @('WriteGPLink')
    Group         = @('WriteMember', 'AddSelf', 'WriteValidated')
    User          = @('ForceChangePassword', 'AllExtendedRights', 'AddKeyCredentialLink', 'WriteSPN', 'WriteScriptPath', 'WriteUAC', 'WriteAccountRestrictions', 'WriteAltSecurityIdentities')
    Computer      = @('ForceChangePassword', 'AllExtendedRights', 'AddKeyCredentialLink', 'WriteSPN', 'WriteRBCD', 'WriteAccountRestrictions', 'WriteAltSecurityIdentities')
    GPO           = @('WriteGPCFileSysPath')
}

function ConvertFrom-ADAuditSidBytes {
    param([byte[]]$Bytes, [int]$Offset = 0)
    if (-not $Bytes -or $Bytes.Length -lt $Offset + 8) { return $null }
    $rev = $Bytes[$Offset]
    $count = $Bytes[$Offset + 1]
    if ($Bytes.Length -lt $Offset + 8 + 4 * $count) { return $null }
    [uint64]$auth = 0
    for ($i = 2; $i -lt 8; $i++) { $auth = ($auth -shl 8) -bor $Bytes[$Offset + $i] }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("S-$rev-$auth")
    for ($i = 0; $i -lt $count; $i++) { [void]$sb.Append('-').Append([BitConverter]::ToUInt32($Bytes, $Offset + 8 + 4 * $i)) }
    return $sb.ToString()
}

function ConvertFrom-ADAuditSecurityDescriptor {
    <#
        Parses a self-relative SECURITY_DESCRIPTOR. Returns OwnerSid and Aces, where each
        ACE has: Allow, Mask, ObjectType, InheritedObjectType (lower-case GUID strings or
        $null), Sid, Inherited, InheritOnly, ContainerInherit. Unknown ACE types are skipped.
    #>
    param([Parameter(Mandatory)][byte[]]$Bytes)

    if ($Bytes.Length -lt 20) { throw 'Security descriptor too short' }
    $control = [BitConverter]::ToUInt16($Bytes, 2)
    if (($control -band 0x8000) -eq 0) { throw 'Not a self-relative security descriptor' }
    $ownerOff = [BitConverter]::ToUInt32($Bytes, 4)
    $daclOff = [BitConverter]::ToUInt32($Bytes, 16)
    $owner = $(if ($ownerOff) { ConvertFrom-ADAuditSidBytes -Bytes $Bytes -Offset $ownerOff } else { $null })

    $aces = New-Object System.Collections.Generic.List[object]
    if ((($control -band 0x0004) -ne 0) -and $daclOff) {   # SE_DACL_PRESENT
        $count = [BitConverter]::ToUInt16($Bytes, $daclOff + 4)
        $p = $daclOff + 8
        for ($i = 0; $i -lt $count; $i++) {
            if ($p + 4 -gt $Bytes.Length) { break }
            $type = $Bytes[$p]; $flags = $Bytes[$p + 1]; $size = [BitConverter]::ToUInt16($Bytes, $p + 2)
            if ($size -lt 8) { break }
            $mask = [BitConverter]::ToUInt32($Bytes, $p + 4)
            $objType = $null; $inhType = $null; $sidOff = $p + 8
            $known = $true
            switch ($type) {
                0 { }                       # ACCESS_ALLOWED
                1 { }                       # ACCESS_DENIED
                { $_ -in 5, 6 } {           # ACCESS_ALLOWED_OBJECT / ACCESS_DENIED_OBJECT
                    $oflags = [BitConverter]::ToUInt32($Bytes, $p + 8)
                    $q = $p + 12
                    if ($oflags -band 1) { $objType = ([Guid]::new([byte[]]$Bytes[$q..($q + 15)])).ToString(); $q += 16 }
                    if ($oflags -band 2) { $inhType = ([Guid]::new([byte[]]$Bytes[$q..($q + 15)])).ToString(); $q += 16 }
                    $sidOff = $q
                }
                default { $known = $false }
            }
            if ($known) {
                $aces.Add([pscustomobject]@{
                        Allow               = ($type -in 0, 5)
                        Mask                = [uint32]$mask
                        ObjectType          = $objType
                        InheritedObjectType = $inhType
                        Sid                 = (ConvertFrom-ADAuditSidBytes -Bytes $Bytes -Offset $sidOff)
                        Inherited           = (($flags -band 0x10) -ne 0)
                        InheritOnly         = (($flags -band 0x08) -ne 0)
                        ContainerInherit    = (($flags -band 0x02) -ne 0)
                    })
            }
            $p += $size
        }
    }
    [pscustomobject]@{ OwnerSid = $owner; Aces = $aces.ToArray() }
}

function Get-ADAuditAceRight {
    <#
        Dangerous rights an ALLOW ACE grants on the object it sits on (inherit-only ACEs
        don't apply to the object itself). Kind: Domain, OU, Group, User, Computer, GPO,
        AdminSDHolder (= User + Group + Computer, since SDProp copies it onto those).
    #>
    param([Parameter(Mandatory)]$Ace, [Parameter(Mandatory)][string]$Kind)

    if (-not $Ace.Allow -or $Ace.InheritOnly) { return @() }
    $m = [int64]$Ace.Mask
    $ot = $Ace.ObjectType
    $r = New-Object System.Collections.Generic.List[string]

    if (($m -band 0x10000000) -or (($m -band 0xF01FF) -eq 0xF01FF)) { $r.Add('GenericAll') }
    else {
        if ($m -band 0x40000) { $r.Add('WriteDacl') }
        if ($m -band 0x80000) { $r.Add('WriteOwner') }
        if ($m -band 0x40000000) { $r.Add('WriteAllProperties'); $r.Add('WriteValidated') }   # raw GENERIC_WRITE
        if ($m -band 0x20) {
            if (-not $ot) { $r.Add('WriteAllProperties') }
            elseif ($script:ADAuditGuid.ContainsKey($ot)) { $r.Add($script:ADAuditGuid[$ot]) }
        }
        if ($m -band 0x8) {
            if (-not $ot) { $r.Add('WriteValidated') }
            elseif ($ot -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2') { $r.Add('AddSelf') }
        }
        if ($m -band 0x100) {
            if (-not $ot) { $r.Add('AllExtendedRights') }
            elseif ($script:ADAuditExtendedRight.ContainsKey($ot)) { $r.Add($script:ADAuditExtendedRight[$ot]) }
        }
    }

    $allowed = @($script:ADAuditRightsByKind.Common)
    if ($Kind -eq 'AdminSDHolder') { $allowed += $script:ADAuditRightsByKind.User + $script:ADAuditRightsByKind.Group + $script:ADAuditRightsByKind.Computer }
    elseif ($script:ADAuditRightsByKind.ContainsKey($Kind)) { $allowed += $script:ADAuditRightsByKind[$Kind] }
    return @($r | Where-Object { $_ -in $allowed } | Select-Object -Unique)
}

function Test-ADAuditAceInheritsTo {
    # ACE on a container that is inherited by child objects of the given class
    param([Parameter(Mandatory)]$Ace, [Parameter(Mandatory)][string]$ClassGuid)
    return $Ace.Allow -and $Ace.ContainerInherit -and ((-not $Ace.InheritedObjectType) -or ($Ace.InheritedObjectType -eq $ClassGuid))
}
