#Requires -Version 5.1
<#
    Smb (PingCastle equivalents: smb, smb3querynetwork-lite)
    Sends only SMB NEGOTIATE packets - the same first packet every SMB client sends.
    No session setup, no authentication, no file access.

      1. SMB2/3 NEGOTIATE (dialects 2.0.2 - 3.0.2) -> highest dialect + whether signing is REQUIRED
      2. SMB1 NEGOTIATE ("NT LM 0.12" only)        -> whether the server still answers SMB1

    Heads-up: if "Audit SMB1 access" is enabled on targets, the SMB1 probe logs
    event 3000 (Microsoft-Windows-SMBServer/Audit). Use -SkipSmb1 to avoid it.
#>

function Read-ADAuditStreamBytes {
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][int]$Count)
    $buf = New-Object byte[] $Count
    $off = 0
    while ($off -lt $Count) {
        $n = $Stream.Read($buf, $off, $Count - $off)
        if ($n -le 0) { return $null }
        $off += $n
    }
    return , $buf
}

function Invoke-ADAuditSmbExchange {
    <#
        Sends one SMB message (direct TCP framing on 445) and returns the response bytes,
        or $null if the server closed/reset the connection. Throws on timeouts.
    #>
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][byte[]]$Packet, [int]$TimeoutMs = 3000)

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($ComputerName, 445, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw "Connection to ${ComputerName}:445 timed out" }
        $client.EndConnect($ar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs

        $frame = New-Object byte[] ($Packet.Length + 4)
        $frame[1] = [byte](($Packet.Length -shr 16) -band 0xFF)
        $frame[2] = [byte](($Packet.Length -shr 8) -band 0xFF)
        $frame[3] = [byte]($Packet.Length -band 0xFF)
        [Array]::Copy($Packet, 0, $frame, 4, $Packet.Length)

        try {
            $stream.Write($frame, 0, $frame.Length)
            $hdr = Read-ADAuditStreamBytes -Stream $stream -Count 4
            if (-not $hdr) { return $null }
            $len = ([int]$hdr[1] -shl 16) -bor ([int]$hdr[2] -shl 8) -bor [int]$hdr[3]
            if ($len -le 0 -or $len -gt 1048576) { return $null }
            $body = Read-ADAuditStreamBytes -Stream $stream -Count $len
            return , $body
        }
        catch [System.IO.IOException] {
            $se = $_.Exception.InnerException -as [System.Net.Sockets.SocketException]
            if ($se -and $se.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) { throw "SMB read from $ComputerName timed out" }
            return $null   # connection reset/closed by server
        }
    }
    finally { $client.Close() }
}

function New-ADAuditSmb2NegotiatePacket {
    $dialects = [uint16[]](0x0202, 0x0210, 0x0300, 0x0302)
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    # SMB2 header (64 bytes)
    $bw.Write([byte[]](0xFE, 0x53, 0x4D, 0x42))
    $bw.Write([uint16]64)       # StructureSize
    $bw.Write([uint16]0)        # CreditCharge
    $bw.Write([uint32]0)        # Status
    $bw.Write([uint16]0)        # Command = NEGOTIATE
    $bw.Write([uint16]1)        # CreditRequest
    $bw.Write([uint32]0)        # Flags
    $bw.Write([uint32]0)        # NextCommand
    $bw.Write([uint64]0)        # MessageId
    $bw.Write([uint32]0)        # Reserved
    $bw.Write([uint32]0)        # TreeId
    $bw.Write([uint64]0)        # SessionId
    $bw.Write((New-Object byte[] 16))  # Signature
    # NEGOTIATE request
    $bw.Write([uint16]36)       # StructureSize
    $bw.Write([uint16]$dialects.Count)
    $bw.Write([uint16]1)        # SecurityMode: signing enabled
    $bw.Write([uint16]0)        # Reserved
    $bw.Write([uint32]0)        # Capabilities
    $bw.Write([guid]::NewGuid().ToByteArray())
    $bw.Write([uint64]0)        # ClientStartTime
    foreach ($d in $dialects) { $bw.Write([uint16]$d) }
    $bw.Flush()
    return , $ms.ToArray()
}

function New-ADAuditSmb1NegotiatePacket {
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    # SMB1 header (32 bytes)
    $bw.Write([byte[]](0xFF, 0x53, 0x4D, 0x42))
    $bw.Write([byte]0x72)       # SMB_COM_NEGOTIATE
    $bw.Write([uint32]0)        # Status
    $bw.Write([byte]0x18)       # Flags
    $bw.Write([uint16]0xC853)   # Flags2
    $bw.Write([uint16]0)        # PIDHigh
    $bw.Write((New-Object byte[] 8))  # SecurityFeatures
    $bw.Write([uint16]0)        # Reserved
    $bw.Write([uint16]0)        # TID
    $bw.Write([uint16]0xFEFF)   # PIDLow
    $bw.Write([uint16]0)        # UID
    $bw.Write([uint16]0)        # MID
    # Body: WordCount=0, ByteCount, dialect "NT LM 0.12"
    [byte[]]$dialect = @([byte]0x02) + [Text.Encoding]::ASCII.GetBytes('NT LM 0.12') + @([byte]0x00)
    $bw.Write([byte]0)
    $bw.Write([uint16]$dialect.Length)
    $bw.Write($dialect)
    $bw.Flush()
    return , $ms.ToArray()
}

function Invoke-ADAuditSmbScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [bool]$IsDomainController,
        [int]$TimeoutMs = 3000,
        [switch]$SkipSmb1
    )

    $dialect = $null; $signingRequired = $null; $signingEnabled = $null; $note = $null
    $resp = Invoke-ADAuditSmbExchange -ComputerName $ComputerName -Packet (New-ADAuditSmb2NegotiatePacket) -TimeoutMs $TimeoutMs
    if ($resp) {
        [byte[]]$r = $resp
        if ($r.Length -ge 70 -and $r[0] -eq 0xFE -and $r[1] -eq 0x53 -and $r[2] -eq 0x4D -and $r[3] -eq 0x42) {
            $status = [BitConverter]::ToUInt32($r, 8)
            if ($status -eq 0) {
                $secMode = [BitConverter]::ToUInt16($r, 66)
                $dialect = '{0}.{1}.{2}' -f (([BitConverter]::ToUInt16($r, 68)) -shr 8), ((([BitConverter]::ToUInt16($r, 68)) -shr 4) -band 0xF), (([BitConverter]::ToUInt16($r, 68)) -band 0xF)
                $signingEnabled = ($secMode -band 0x1) -ne 0
                $signingRequired = ($secMode -band 0x2) -ne 0
            }
            else { $note = ('SMB2 negotiate status 0x{0:X8}' -f $status) }
        }
        else { $note = 'Unexpected SMB2 negotiate response' }
    }
    else { $note = 'SMB2 negotiate rejected' }

    $smb1 = 'NotTested'
    if (-not $SkipSmb1) {
        $r1 = Invoke-ADAuditSmbExchange -ComputerName $ComputerName -Packet (New-ADAuditSmb1NegotiatePacket) -TimeoutMs $TimeoutMs
        if ($r1 -and $r1.Count -ge 4 -and $r1[0] -eq 0xFF -and $r1[1] -eq 0x53 -and $r1[2] -eq 0x4D -and $r1[3] -eq 0x42) { $smb1 = 'Enabled' }
        else { $smb1 = 'Disabled' }
    }

    $issues = @(); $sev = @()
    if ($smb1 -eq 'Enabled') {
        $issues += 'SMBv1 enabled'
        $sev += $(if ($IsDomainController) { 'High' } else { 'Medium' })
    }
    if ($signingRequired -eq $false) {
        $issues += 'SMB signing not required (NTLM relay target)'
        $sev += $(if ($IsDomainController) { 'High' } else { 'Low' })
    }
    if ($note -and $null -eq $signingRequired) { $issues += $note; $sev += 'Info' }

    New-ADAuditResult -Scanner 'Smb' -Computer $ComputerName -Severity (Get-ADAuditMaxSeverity $sev) -Finding ($issues -join '; ') -Data ([ordered]@{
        IsDomainController = $IsDomainController
        Smb2Dialect        = $dialect
        SigningEnabled     = $signingEnabled
        SigningRequired    = $signingRequired
        Smb1               = $smb1
        IssueSeverity = (@($sev) -join ';')
    })
}
