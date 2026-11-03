# ADAuditScanners

Read-only PowerShell AD audit scanners, modeled on PingCastle's health-check rules and `--scanner` modules. No module dependencies (uses `System.DirectoryServices` and netapi32), Windows PowerShell 5.1 or PowerShell 7 on Windows.

**Nothing is written to Active Directory or to scanned hosts.**

## Quick start

```powershell
# From a domain-joined machine, as a domain user
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-ADAudit.ps1                                   # everything
.\Invoke-ADAudit.ps1 -Scanners DomainPolicy,Accounts,Groups,OSInventory,LapsBitLocker   # AD-only, no host traffic
.\Invoke-ADAudit.ps1 -Scanners Smb,Spooler -DomainControllersOnly
.\Invoke-ADAudit.ps1 -Server dc01.corp.local -Credential (Get-Credential)            # LDAP as another account
```

Output goes to `.\ADAudit-<timestamp>\`: one CSV per scanner, `AllFindings.csv` (everything not OK), and `Summary.html`.

## Scanners

| Scanner | Type | What it checks |
|---|---|---|
| DomainPolicy | LDAP | Min password length, history, max age, lockout threshold, MachineAccountQuota, krbtgt password age, Guest enabled, Anonymous/Everyone in Pre-Windows 2000 Compatible Access, functional level, FGPP count |
| Accounts | LDAP | Privileged accounts (direct + nested), service accounts (SPN or name pattern) and gMSAs, password never expires, password not required, reversible encryption, DES-only, never logged on, stale, old passwords, Kerberoastable (SPN on user), AS-REP roastable, unconstrained/constrained delegation (users and non-DC computers), too many group memberships, sIDHistory, orphaned adminCount=1, admins not in Protected Users / not "sensitive", password-like text in description |
| Groups | LDAP | Every member of Administrators, Domain/Enterprise/Schema Admins, Account/Server/Print/Backup Operators, GPO Creator Owners, Key Admins, DnsAdmins, with Direct/Nested; computers, foreign principals, disabled accounts in those groups; operator groups that aren't empty; group nesting deeper than `-MaxNestingDepth`; circular nesting |
| OSInventory | LDAP | Unsupported / ending-soon Windows versions (built-in lifecycle table, late 2026), stale computer accounts |
| LapsBitLocker | LDAP | Legacy and Windows LAPS coverage and expiry, BitLocker recovery key escrow (reads timestamps/object existence only, never passwords or keys) |
| Spooler | TCP 445 | Print Spooler pipe reachable (High on DCs) |
| Smb | TCP 445 | SMBv1 enabled, SMB signing required, highest SMB2/3 dialect (NEGOTIATE packets only, no auth) |
| LocalAdmin | TCP 445 | Members of BUILTIN\Administrators; flags Everyone/Domain Users/Authenticated Users, orphaned SIDs, individual users |
| Share | TCP 445 | Disk shares and whether the scanning account can list each share root (reads one directory entry at most) |

## Tuning

| Parameter | Default | Purpose |
|---|---|---|
| `-ActiveDays` | 90 | Stale threshold for users and computers; host scanners only target computers active within this window |
| `-PasswordAgeDays` | 365 | Old password threshold |
| `-MaxGroupMemberships` | 20 | Flag users in more groups than this |
| `-MaxNestingDepth` | 3 | Flag groups nested deeper than this |
| `-ServiceAccountPattern` | `^(svc\|srv\|sa\|sql\|app\|service)[-_.]...` | Regex for service-account naming in your org |
| `-Throttle` | 16 | Hosts scanned in parallel |
| `-TimeoutSeconds` / `-NetworkTimeoutMs` | 120 / 3000 | Per-host and per-connection timeouts |
| `-SkipSmb1` | off | Skip the SMB1 probe (see notes) |
| `-ComputerName`, `-DomainControllersOnly` | | Limit host scanners |

## Which account to run as

- **AD-only scanners:** any domain user works. BitLocker recovery objects are usually visible only to Domain Admins; otherwise the result shows `NotVisible` rather than false findings.
- **LocalAdmin:** needs local admin on targets (Windows 10 1607+ / Server 2016+ restrict remote SAM to admins). Non-admin runs show "Access denied".
- **Share:** run as a *plain domain user*. Any share root that account can list is readable by every domain user. To use another identity for host scans: `runas /netonly /user:CORP\audituser powershell.exe`.

## Safety notes

- Host scanners only make reads: TCP connect, SMB NEGOTIATE, the spoolss pipe attributes, NetLocalGroupGetMembers, NetShareEnum and one directory listing per share. They do not use zerologon, null-session, coercion or exploit checks.
- If "Audit SMB1 access" is enabled on targets, the SMB1 probe logs event 3000. Use `-SkipSmb1` if that is a concern.
- EDR/IDS may alert on many SMB connections from one host. Tell your SOC first, or lower `-Throttle`.
- The Windows lifecycle dates are a static table. Check https://learn.microsoft.com/lifecycle before you act on them.
- Enterprise/Schema Admins live in the forest root domain. When you scan a child domain, run it again against the root (`-Server rootdc`) to cover them.
