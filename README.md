# dtecht-AD

Read-only PowerShell AD audit scanners, modeled on PingCastle's health-check rules and `--scanner` modules. No module dependencies (uses `System.DirectoryServices` and netapi32), Windows PowerShell 5.1 or PowerShell 7 on Windows.

**Read-only: nothing is written to Active Directory, DCs or scanned hosts.** The only files written are the reports in `-OutputPath`, which must be a local folder.

### What touches other systems

| Target | Calls | Writes |
|---|---|---|
| AD | LDAP searches only (signed + sealed bind, `ReadonlyServer`), owner + DACL of security descriptors | None |
| DC Security log | `Get-WinEvent` queries | None |
| SYSVOL | `Get-Content`, `Import-Csv`, `Get-Acl` on GPO files/folders | None |
| Scanned hosts | TCP connect, SMB NEGOTIATE (no session), spooler pipe attributes, `NetLocalGroupGetMembers`, `NetShareEnum`, `LookupAccountSid`, one directory listing per share | None |

`tests/Test-ReadOnly.ps1` enforces this, including for the packaged files in `dist/` (each line is mapped back to its source file). It parses every script and fails on any command outside a read-only allowlist (including external tools such as auditpol or net), any ADSI/registry/WMI/file write method, any assignment to directory entry properties, unexpected native APIs, or a DirectoryEntry created outside `lib/Common.ps1`. Run it before merging changes: `pwsh -File tests/Test-ReadOnly.ps1`.

Side effects that every authenticated read causes: logon/Kerberos events on DCs and hosts, a bad-password count if `-Credential` is mistyped, and SMB1 audit event 3000 when that audit is on (`-SkipSmb1` avoids it).

## Quick start

Pick one. All three run the same tool; parameters are identical.

**1. One file (easiest, works offline).** Copy `dist/dtecht-AD.ps1` to a domain-joined machine and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\dtecht-AD.ps1 -Preset ADOnly -OpenReport
```

**2. Download and run (machine with internet access):**

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
irm https://raw.githubusercontent.com/techdetechtives/dtecht-AD/main/dist/dtecht-AD.ps1 -OutFile dtecht-AD.ps1
(Get-FileHash .\dtecht-AD.ps1).Hash      # compare with dist/SHA256SUMS
powershell -ExecutionPolicy Bypass -File .\dtecht-AD.ps1 -Preset ADOnly -OpenReport
```

**3. PowerShell module.** Copy the `dist/dtecht-AD` folder into a module path (e.g. `C:\Program Files\WindowsPowerShell\Modules`), then from any prompt:

```powershell
dtecht-ad -Preset ADOnly -OpenReport          # dtecht-ad is an alias of Invoke-DtechtAD
Get-Help Invoke-DtechtAD -Full
```

From a clone of this repo, `.\Invoke-ADAudit.ps1` works the same way.

### Presets

| Preset | Runs | Traffic |
|---|---|---|
| `Full` (default) | Every scanner | LDAP/SYSVOL, DC event logs, TCP 445 to active computers |
| `ADOnly` | DomainPolicy, Accounts, Groups, OSInventory, LapsBitLocker, DomainControllers, AuditPolicy, Permissions | LDAP + SYSVOL only, nothing sent to member hosts |
| `DCsOnly` | AD checks + Events, Spooler, SMB on domain controllers only | DCs only |
| `HostsOnly` | Spooler, Smb, LocalAdmin, Share | TCP 445 to active computers |

`-Scanners` overrides the preset. More examples:

```powershell
.\dtecht-AD.ps1                                                    # everything
.\dtecht-AD.ps1 -Preset DCsOnly -EventDays 30                      # DCs, plus 30 days of account/group changes
.\dtecht-AD.ps1 -Baseline .\ADAudit-20261101-090000               # what changed since that run
.\dtecht-AD.ps1 -Server dc01.corp.local -Credential (Get-Credential)   # LDAP as another account
.\dtecht-AD.ps1 -Scanners Smb,Spooler -ComputerName srv01,srv02
```

Output goes to `.\ADAudit-<timestamp>\`:

| File | Contents |
|---|---|
| `<Scanner>.csv` | All rows from that scanner |
| `AllFindings.csv` | One row per issue that isn't OK, with Severity, Category, Rule and Remediation |
| `results.json` | All results plus run metadata, for a later `-Baseline` or for pushing into a SIEM/platform |
| `Changes.csv` | Only with `-Baseline`: what changed since the earlier run |
| `Summary.html` | Risk score per category, rules triggered with remediation, changes since baseline, High/Medium findings, recent DC changes |

## Risk score

Every finding is mapped to a rule (e.g. *DCSync rights for non-DC accounts*, *Password never expires*) with remediation text, and each rule belongs to one of seven categories: Privileged Access, Permissions, Kerberos & Delegation, Passwords & Credentials, Host Hardening, Monitoring & Audit, Stale Objects & Hygiene.

Scoring works like PingCastle: lower is better, 0–100 per category. Each triggered rule counts **once**, at the highest severity seen (High 15, Medium 8, Low 3 points), so 2,000 stale accounts don't outweigh one DCSync finding. The overall score is the worst category. Info findings and Events (activity, not posture) aren't scored. Scores are also stored in `results.json` (`Meta.Score`), so you can track them over time.

## Comparing runs (`-Baseline`)

Point `-Baseline` at an earlier output folder (or its `results.json`). Changes are reported as:

- **Added / Removed:** members of privileged groups (direct or nested). Every Added row is High.
- **Changed:** DomainPolicy settings whose value changed, e.g. MachineAccountQuota 10 → 0.
- **New / Resolved:** individual findings, e.g. an account newly set to *password never expires*, a new SPN on a user, new delegation, a host where SMBv1 was turned off.

Numbers and dates inside findings are normalised, so "password is 400 days old" and "401 days old" count as the same finding. Host findings are only marked Resolved when the host was actually scanned again, so an unreachable host doesn't look fixed. Only scanners that ran in both runs are compared. Events are time-windowed and aren't compared.

A simple routine: run weekly as a scheduled task with `-Baseline` pointing at the previous week's folder, and review `Changes.csv`.

## Scanners

| Scanner | Type | What it checks |
|---|---|---|
| DomainPolicy | LDAP | Min password length, history, max age, lockout threshold, MachineAccountQuota, krbtgt password age, Guest enabled, Anonymous/Everyone in Pre-Windows 2000 Compatible Access, functional level, each fine-grained password policy (reversible encryption, admin policy under 14 chars, policies that apply to nothing), admins with only the default policy |
| Accounts | LDAP | Privileged accounts (direct, nested and via primaryGroupID), service accounts (SPN or name pattern) and gMSAs, password never expires, password not required, reversible encryption, DES-only, never logged on, stale, old passwords, Kerberoastable (SPN on user), AS-REP roastable, unconstrained/constrained delegation (users and non-DC computers), too many group memberships, sIDHistory, orphaned adminCount=1, admins not in Protected Users / not "sensitive", password-like text in description, cleartext passwords in `userPassword` / `unixUserPassword` / `msSFU30Password` / `os400Password`, unexpected primaryGroupID on users and computers |
| Groups | LDAP | Every member of Administrators, Domain/Enterprise/Schema Admins, Account/Server/Print/Backup Operators, GPO Creator Owners, Key Admins, DnsAdmins, with Direct/Nested; computers, foreign principals, disabled accounts in those groups; operator groups that aren't empty; group nesting deeper than `-MaxNestingDepth`; circular nesting; hidden admin membership via primaryGroupID; more than `-MaxDomainAdmins` enabled users in Domain/Enterprise Admins or Administrators; empty groups and OUs |
| OSInventory | LDAP | Unsupported / ending-soon Windows versions (built-in lifecycle table, late 2026), stale computer accounts |
| LapsBitLocker | LDAP | Legacy and Windows LAPS coverage and expiry, BitLocker recovery key escrow (reads timestamps/object existence only, never passwords or keys) |
| DomainControllers | LDAP + DNS | Every DC with site, IPs, OS, RODC/Global Catalog, FSMO roles. Flags: only one writable DC, DC account not seen for 30+ days, FSMO role held by a deleted DC, leftover NTDS Settings with no DC |
| AuditPolicy | LDAP + SYSVOL | Audit policy GPOs give DCs (domain + Domain Controllers OU links, honouring disabled/enforced links, block inheritance and disabled computer settings). Reads `audit.csv` and `GptTmpl.inf`, flags missing subcategories (Security Group Management, User Account Management, Directory Service Changes, Kerberos, etc.) and Security log size |
| Permissions | LDAP + SYSVOL | Reads owner + DACL of key objects (one hop, no BloodHound). **DCSync** rights on the domain root; dangerous rights for non-Tier-0 principals (GenericAll, WriteDacl, WriteOwner, write all properties, all extended rights, add member, reset password, add key credential / shadow credentials, write SPN, RBCD, logon script, altSecurityIdentities, gPLink) on the domain root, AdminSDHolder, Domain Controllers OU, DC computers, krbtgt, privileged groups and their members; non-Tier-0 **owners** of those objects; who can **edit GPOs** (AD object and SYSVOL folder; High when the GPO applies to DCs or the domain); who can **read LAPS passwords** (where the delegation is set); who can **read gMSA passwords**. Broad groups (Everyone, Authenticated Users, Domain Users...) are called out |
| Events | RPC to DCs | Security log for the last `-EventDays`: users created/enabled/disabled/deleted/renamed/locked, password resets, computer accounts created, members added/removed from groups (High for privileged groups), SID history, DSRM password set, 4738 changes that matter (delegation, pre-auth off, password not required, SID history, primary group), and 5136 changes to SPN, delegation/RBCD, shadow credentials (msDS-KeyCredentialLink), sIDHistory, ACLs on AdminSDHolder/domain root, gPLink, logon scripts. Also reports how far back each DC's Security log actually goes |
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
| `-ComputerName`, `-DomainControllersOnly` | | Limit host scanners (and which DCs Events reads) |
| `-EventDays` / `-EventMaxPerDC` | 7 / 5000 | Events time window and per-DC cap |
| `-Baseline` | | Earlier run folder or `results.json` to compare against |
| `-MaxDomainAdmins` | 5 | Flag Domain/Enterprise Admins or Administrators with more enabled users |
| `-SkipSysvol` | off | Permissions: don't read GPO folder ACLs in SYSVOL |

## Which account to run as

- **AD-only scanners:** any domain user works. BitLocker recovery objects are usually visible only to Domain Admins; otherwise the result shows `NotVisible` rather than false findings.
- **LocalAdmin:** needs local admin on targets (Windows 10 1607+ / Server 2016+ restrict remote SAM to admins). Non-admin runs show "Access denied".
- **Events:** the account must be in **Event Log Readers** on DCs (or be a Domain Admin), and TCP 135 + dynamic RPC ports to DCs must be open. Events only show up if the audit subcategories are on, so check the AuditPolicy scanner. 5136 events also need SACLs on the objects.
- **Permissions:** any domain user can read the owner and DACL of these objects. Principals are not expanded, so check who is in a flagged group. Only Allow ACEs are evaluated; a Deny ACE could block a reported right in rare cases.
- **AuditPolicy:** any domain user. SYSVOL is read over SMB with your current Windows logon, not `-Credential`.
- **Share:** run as a *plain domain user*. Any share root that account can list is readable by every domain user. To use another identity for host scans: `runas /netonly /user:CORP\audituser powershell.exe`.

## Safety notes

- Host scanners only make reads: TCP connect, SMB NEGOTIATE, the spoolss pipe attributes, NetLocalGroupGetMembers, NetShareEnum and one directory listing per share. They do not use zerologon, null-session, coercion or exploit checks.
- If "Audit SMB1 access" is enabled on targets, the SMB1 probe logs event 3000. Use `-SkipSmb1` if that is a concern.
- EDR/IDS may alert on many SMB connections from one host. Tell your SOC first, or lower `-Throttle`.
- The Windows lifecycle dates are a static table. Check https://learn.microsoft.com/lifecycle before you act on them.
- Events only reads the Security log (`Get-WinEvent`); it never clears or changes it. AuditPolicy only reads GPO files. To change audit policy, use Group Policy, not this tool.
- AuditPolicy can't see GPOs linked to AD sites, local policy, or `auditpol` changes made by hand. To confirm on a DC: `auditpol /get /category:*`.
- If DCs already forward Security logs to a SIEM (e.g. TechDetechtives via Winlogbeat), do real-time detection there. Use the Events scanner for periodic review and to check log coverage.
- Enterprise/Schema Admins live in the forest root domain. When you scan a child domain, run it again against the root (`-Server rootdc`) to cover them.

## Authorized use

Run dtecht-AD only against Active Directory environments you own or are explicitly authorized to audit. Reports contain sensitive data about your domain (admin accounts, permissions, weaknesses), so store and share them accordingly. The `.gitignore` keeps report output out of git.

## License

MIT - see [LICENSE](LICENSE). Some checks are inspired by [PingCastle](https://github.com/netwrix/pingcastle), [EthicalInsight](https://github.com/AlchemiistCreative/EthicalInsight) and [AD_Miner](https://github.com/AD-Security/AD_Miner); no code from those projects is included.

## Development

Edit the sources (`Invoke-ADAudit.ps1`, `lib/`, `Scanners/`), never `dist/`. Then:

```powershell
pwsh -File tests/Test-ReadOnly.ps1        # read-only guard
pwsh -File build/Build-Package.ps1        # regenerate dist/dtecht-AD.ps1, the module and SHA256SUMS
pwsh -File build/Build-Package.ps1 -Check # fails if dist/ is out of date
```
