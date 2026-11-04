#Requires -Version 5.1
<#
    Rules: maps each finding (one issue of a result row) to a category, a rule title
    and remediation text, and computes risk scores.

    Scoring (PingCastle-style, lower is better, 0-100 per category):
      each triggered rule counts once, at the highest severity seen for it:
      High = 15, Medium = 8, Low = 3 points; category score is capped at 100.
      Overall score = the worst category. Info/OK/Error rows and the Events
      scanner (activity, not posture) are not scored.
#>

$script:ADAuditCategories = @('Privileged Access', 'Permissions', 'Kerberos & Delegation', 'Passwords & Credentials', 'Host Hardening', 'Monitoring & Audit', 'Stale Objects & Hygiene')
$script:ADAuditScannerCategory = @{
    Accounts = 'Passwords & Credentials'; Groups = 'Privileged Access'; DomainPolicy = 'Passwords & Credentials'; OSInventory = 'Host Hardening'
    LapsBitLocker = 'Passwords & Credentials'; DomainControllers = 'Stale Objects & Hygiene'; AuditPolicy = 'Monitoring & Audit'; Events = 'Recent Changes'
    Spooler = 'Host Hardening'; Smb = 'Host Hardening'; LocalAdmin = 'Host Hardening'; Share = 'Permissions'; Permissions = 'Permissions'
}
$script:ADAuditPoints = @{ High = 15; Medium = 8; Low = 3 }

# First match wins: put specific patterns before general ones.
$script:ADAuditRules = @(
    # --- Permissions ---
    @{ T = 'DCSync rights for non-DC accounts'; C = 'Permissions'; P = 'Can DCSync|one right short of DCSync'; R = 'Remove Replicating Directory Changes / Changes All from the domain root for everyone except DCs and the Entra Connect sync account; treat that account as Tier 0.' }
    @{ T = 'Dangerous rights on Tier-0 objects'; C = 'Permissions'; P = '^Dangerous rights for non-Tier-0'; R = 'Remove the ACE from the object (and from AdminSDHolder if it is set there, or SDProp will put it back). Only Tier-0 groups should be able to change Tier-0 objects.' }
    @{ T = 'Non-Tier-0 owner of Tier-0 object'; C = 'Permissions'; P = '^Non-Tier-0 owner'; R = 'Change the owner to Domain Admins. An owner can always rewrite the ACL.' }
    @{ T = 'Non-admin can edit GPOs'; C = 'Permissions'; P = '^Can edit GPO|^GPO owned by|^Can modify GPO files'; R = 'Remove edit rights from the GPO (GPMC > Delegation) and its SYSVOL folder. Only Tier 0 should edit GPOs that apply to DCs or the whole domain.' }
    @{ T = 'LAPS password readers'; C = 'Permissions'; P = '^Can read LAPS passwords'; R = 'Limit LAPS password read to dedicated admin groups per tier (Set-LapsADReadPasswordPermission / Set-AdmPwdReadPasswordPermission).' }
    @{ T = 'gMSA password readers'; C = 'Permissions'; P = 'gMSA password|password of privileged gMSA'; R = 'Limit PrincipalsAllowedToRetrieveManagedPassword to the servers that run the service.' }
    @{ T = 'Anyone can join computers (MachineAccountQuota)'; C = 'Permissions'; P = 'can join up to'; R = 'Set ms-DS-MachineAccountQuota to 0 and delegate computer joins to a specific group.' }
    @{ T = 'Anonymous AD enumeration'; C = 'Permissions'; P = 'Pre-Windows 2000 Compatible Access'; R = 'Remove Anonymous Logon and Everyone from Pre-Windows 2000 Compatible Access.' }
    @{ T = 'Share readable by scanning account'; C = 'Permissions'; P = 'Share root listable'; R = 'Review share and NTFS permissions; remove Everyone, Authenticated Users and Domain Users where not needed.' }
    # --- Privileged access ---
    @{ T = 'Hidden admin membership (primaryGroupID)'; C = 'Privileged Access'; P = 'Hidden membership|Primary group is privileged|DC primaryGroupID'; R = 'Set primaryGroupID back to 513 (users) / 515 (computers); add explicit membership only if really needed.' }
    @{ T = 'Operator / Schema / Enterprise Admins not empty'; C = 'Privileged Access'; P = 'should normally be empty'; R = 'Empty these groups; add members only temporarily for a specific task.' }
    @{ T = 'Too many admins'; C = 'Privileged Access'; P = '^Too many admins'; R = 'Keep Domain/Enterprise Admins to a few named admin accounts; delegate day-to-day tasks instead.' }
    @{ T = 'Computer account in admin group'; C = 'Privileged Access'; P = 'Computer account in privileged group'; R = 'Remove computer accounts from admin groups; grant only the specific right needed.' }
    @{ T = 'Foreign principal in admin group'; C = 'Privileged Access'; P = 'Foreign \(cross-trust\) principal'; R = 'Remove accounts from other domains/forests from admin groups.' }
    @{ T = 'gMSA in admin group'; C = 'Privileged Access'; P = 'gMSA in privileged group'; R = 'Confirm the service needs Tier-0 rights; otherwise delegate only what it needs.' }
    @{ T = 'Disabled account in admin group'; C = 'Privileged Access'; P = 'Disabled account still in privileged group'; R = 'Remove disabled accounts from admin groups.' }
    @{ T = 'Admins not in Protected Users'; C = 'Privileged Access'; P = 'not in Protected Users'; R = 'Add admin accounts to Protected Users (test first: blocks NTLM, delegation, DES/RC4 and cached logons).' }
    @{ T = "Admins not 'sensitive and cannot be delegated'"; C = 'Privileged Access'; P = 'sensitive and cannot be delegated'; R = "Set 'Account is sensitive and cannot be delegated' on all admin accounts." }
    @{ T = 'SID history'; C = 'Privileged Access'; P = 'sIDHistory|SID history'; R = 'Remove sIDHistory after migration; keep SID filtering enabled on trusts.' }
    @{ T = 'Guest account enabled'; C = 'Privileged Access'; P = 'Built-in Guest .* is enabled'; R = 'Disable the Guest account.' }
    # --- Kerberos & delegation ---
    @{ T = 'AS-REP roastable accounts'; C = 'Kerberos & Delegation'; P = 'pre-auth not required|Require Preauth enabled'; R = "Clear 'Do not require Kerberos preauthentication'. If an app needs it, give the account a long random password." }
    @{ T = 'Unconstrained delegation'; C = 'Kerberos & Delegation'; P = 'nconstrained delegation|Trusted For Delegation enabled'; R = 'Remove unconstrained delegation; use constrained or resource-based delegation, and protect admins (Protected Users / sensitive flag).' }
    @{ T = 'Delegation with protocol transition'; C = 'Kerberos & Delegation'; P = 'protocol transition|Authenticate For Delegation'; R = 'Use Kerberos-only constrained delegation unless protocol transition is really required.' }
    @{ T = 'Constrained / resource-based delegation'; C = 'Kerberos & Delegation'; P = 'Constrained delegation|Delegation set to|delegation target|Resource-based constrained'; R = 'Confirm each delegation is needed. Delegation to services on DCs (ldap/cifs/host) is Tier 0.' }
    @{ T = 'Kerberoastable admin accounts'; C = 'Kerberos & Delegation'; P = 'Privileged account has SPN'; R = 'Remove SPNs from admin accounts; run services as gMSAs.' }
    @{ T = 'Kerberoastable user accounts'; C = 'Kerberos & Delegation'; P = 'has SPN|SPN added on user'; R = 'Move the service to a gMSA, or use a 25+ character random password and AES only.' }
    @{ T = 'DES-only Kerberos'; C = 'Kerberos & Delegation'; P = 'DES-only|Use DES Key Only'; R = "Clear 'Use only Kerberos DES encryption types'; use AES." }
    @{ T = 'Old krbtgt password'; C = 'Kerberos & Delegation'; P = 'krbtgt password'; R = 'Reset the krbtgt password twice, waiting for replication in between (e.g. Microsoft New-KrbtgtKeys.ps1).' }
    # --- Passwords & credentials ---
    @{ T = 'Cleartext password attributes'; C = 'Passwords & Credentials'; P = 'Cleartext password stored'; R = 'Clear the attribute and change the password; these attributes are readable by most users.' }
    @{ T = 'Password in description'; C = 'Passwords & Credentials'; P = 'Description may contain a password'; R = "Remove the password from the description and change the account's password." }
    @{ T = 'Reversible password encryption'; C = 'Passwords & Credentials'; P = 'eversible password encryption'; R = "Disable 'Store password using reversible encryption' and reset affected passwords." }
    @{ T = 'Password not required'; C = 'Passwords & Credentials'; P = 'Password not required|PASSWD_NOTREQD'; R = 'Clear the flag (Set-ADAccountControl -PasswordNotRequired $false) and set a strong password.' }
    @{ T = 'Password never expires'; C = 'Passwords & Credentials'; P = 'Password never expires'; R = "Turn off 'Password never expires'; for service accounts use gMSAs (automatic rotation)." }
    @{ T = 'Old passwords'; C = 'Passwords & Credentials'; P = '^Password is .* days old'; R = 'Rotate the password; move service accounts to gMSAs.' }
    @{ T = 'No admin password policy'; C = 'Passwords & Credentials'; P = 'Admins only have the default password policy|Admin fine-grained policy'; R = 'Create a fine-grained password policy for admin groups with 14+ characters.' }
    @{ T = 'Weak default password policy'; C = 'Passwords & Credentials'; P = 'minimum length is|^Password history is'; R = 'Minimum length 12+ (14+ for admins), history 24; use fine-grained policies where needed.' }
    @{ T = 'No account lockout'; C = 'Passwords & Credentials'; P = 'No account lockout'; R = 'Set an account lockout threshold (e.g. 10) to slow password spraying.' }
    @{ T = 'Computers without LAPS'; C = 'Passwords & Credentials'; P = 'No LAPS'; R = 'Deploy Windows LAPS to all workstations and member servers.' }
    @{ T = 'LAPS password not rotating'; C = 'Passwords & Credentials'; P = 'LAPS password past expiry'; R = 'Check the LAPS policy and client on these hosts.' }
    # --- Host hardening ---
    @{ T = 'Print Spooler on DCs'; C = 'Host Hardening'; P = 'Print Spooler reachable on a domain controller'; R = 'Stop and disable the Print Spooler service on all DCs.' }
    @{ T = 'SMBv1 enabled'; C = 'Host Hardening'; P = 'SMBv1 enabled'; R = 'Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false) and remove the feature.' }
    @{ T = 'SMB signing not required'; C = 'Host Hardening'; P = 'SMB signing not required'; R = "Require SMB signing by GPO: 'Microsoft network server: Digitally sign communications (always)'." }
    @{ T = 'Individual local admins'; C = 'Host Hardening'; P = 'Individual user account is a local admin'; R = 'Grant local admin through groups, not individual accounts.' }
    @{ T = 'Broad groups are local admins'; C = 'Host Hardening'; P = 'is a local admin'; R = 'Remove broad groups from local Administrators; use LAPS and a dedicated admin group per tier.' }
    @{ T = 'Unsupported operating systems'; C = 'Host Hardening'; P = 'Out of support since'; R = 'Upgrade, or isolate the host until it can be replaced; it gets no security updates.' }
    @{ T = 'OS support ending soon'; C = 'Host Hardening'; P = 'Support ends'; R = 'Plan the upgrade before the end-of-support date.' }
    @{ T = 'No BitLocker key in AD'; C = 'Host Hardening'; P = 'No BitLocker recovery key'; R = 'Enable BitLocker and back up recovery keys to AD.' }
    # --- Monitoring & audit ---
    @{ T = 'Missing DC audit policy'; C = 'Monitoring & Audit'; P = 'not audited'; R = "Enable the subcategory under Advanced Audit Policy Configuration in the DC GPO, and set 'Audit: Force audit policy subcategory settings' to Enabled." }
    @{ T = 'Short Security log retention'; C = 'Monitoring & Audit'; P = 'Security log max size|Security log only covers'; R = 'Raise the DC Security log size (1-4 GB) and forward logs to a SIEM.' }
    # --- Stale objects & hygiene ---
    @{ T = 'FSMO role on deleted DC'; C = 'Stale Objects & Hygiene'; P = 'held by a deleted DC'; R = 'Seize the role to a live DC (Move-ADDirectoryServerOperationMasterRole -Force) and clean up metadata.' }
    @{ T = 'Stale or leftover DCs'; C = 'Stale Objects & Hygiene'; P = 'DC account not seen|DC account has never|leftover metadata|No site server object'; R = 'If the DC was removed, run metadata cleanup; otherwise check replication.' }
    @{ T = 'Single writable DC'; C = 'Stale Objects & Hygiene'; P = 'writable DC in the domain'; R = 'Add a second writable DC.' }
    @{ T = 'Orphaned adminCount'; C = 'Stale Objects & Hygiene'; P = 'adminCount=1 but no longer privileged'; R = "Clear adminCount and re-enable inheritance on the account's ACL." }
    @{ T = 'Never-used accounts'; C = 'Stale Objects & Hygiene'; P = 'Never logged on'; R = 'Disable, then delete after a review period.' }
    @{ T = 'Inactive accounts'; C = 'Stale Objects & Hygiene'; P = 'No logon in|not seen recently|stale'; R = 'Disable inactive accounts and delete after a grace period; automate it.' }
    @{ T = 'Too many group memberships'; C = 'Stale Objects & Hygiene'; P = '^Member of .* groups'; R = 'Review and remove group memberships that are no longer needed.' }
    @{ T = 'Circular / deep group nesting'; C = 'Stale Objects & Hygiene'; P = 'Circular group nesting|levels deep'; R = 'Break nesting loops and flatten deep nesting so access stays reviewable.' }
    @{ T = 'Unexpected primaryGroupID'; C = 'Stale Objects & Hygiene'; P = 'Unexpected primaryGroupID'; R = 'Set primaryGroupID back to the default for the account type.' }
    @{ T = 'Orphaned SIDs in local admins'; C = 'Stale Objects & Hygiene'; P = 'Orphaned'; R = 'Remove unresolvable SIDs from local groups.' }
    @{ T = 'Old domain functional level'; C = 'Stale Objects & Hygiene'; P = 'Functional level'; R = 'Raise the functional level once all DCs run a supported OS.' }
    @{ T = 'Unused fine-grained policy'; C = 'Stale Objects & Hygiene'; P = 'applies to nothing'; R = 'Delete the policy or link it to the intended group.' }
    @{ T = 'Empty groups / OUs'; C = 'Stale Objects & Hygiene'; P = '^Empty (group|OU)'; R = 'Delete if unused.' }
)

function Get-ADAuditIssue {
    <#
        Splits a result row into issues: Scanner, Target, Severity (per issue when the
        row has IssueSeverity), Issue text.
    #>
    param([Parameter(Mandatory)]$Row)
    $texts = @(Split-ADAuditFinding ([string]$Row.Finding))
    if (-not $texts) { return }
    $sevs = @()
    if ($Row.PSObject.Properties['IssueSeverity'] -and $Row.IssueSeverity) { $sevs = @(([string]$Row.IssueSeverity) -split ';') }
    $useSev = $sevs.Count -eq $texts.Count
    for ($i = 0; $i -lt $texts.Count; $i++) {
        [pscustomobject]@{
            Scanner  = $Row.Scanner
            Target   = $Row.Target
            Severity = $(if ($useSev) { $sevs[$i] } else { $Row.Severity })
            Issue    = $texts[$i].Trim()
        }
    }
}

function Get-ADAuditRule {
    param([string]$Scanner, [string]$Issue)
    if ($Scanner -eq 'Events') { return @{ T = 'Recent change (Events)'; C = 'Recent Changes'; R = 'Confirm the change was authorised; if not, treat as an incident.' } }
    foreach ($r in $script:ADAuditRules) { if ($Issue -match $r.P) { return $r } }
    $cat = $script:ADAuditScannerCategory[$Scanner]; if (-not $cat) { $cat = 'Stale Objects & Hygiene' }
    return @{ T = "$Scanner finding"; C = $cat; R = '' }
}

function Get-ADAuditEnrichedFinding {
    <# All issues that are not OK, with Category / Rule / Remediation #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)
    foreach ($row in $Rows) {
        if ($row.Severity -eq 'OK') { continue }
        foreach ($i in (Get-ADAuditIssue -Row $row)) {
            if ($i.Severity -eq 'OK') { continue }
            $rule = Get-ADAuditRule -Scanner $i.Scanner -Issue $i.Issue
            $title = $rule.T
            if ($i.Severity -eq 'Info' -and $title -eq "$($i.Scanner) finding") { $title = 'Information' }
            [pscustomobject][ordered]@{
                Severity    = $i.Severity
                Category    = $rule.C
                Rule        = $title
                Scanner     = $i.Scanner
                Target      = $i.Target
                Finding     = $i.Issue
                Remediation = $rule.R
            }
        }
    }
}

function Get-ADAuditScore {
    <#
        Returns: Overall (0-100), Categories (Category, Score, Rules, High, Medium, Low),
        Rules (Category, Rule, Severity, Objects, Points, Remediation)
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings)
    $rank = @{ High = 3; Medium = 2; Low = 1 }
    $rules = @{}
    foreach ($f in $Findings) {
        if ($f.Scanner -in 'Events', 'Runner', 'Reachability') { continue }
        if (-not $rank.ContainsKey([string]$f.Severity)) { continue }
        $k = "$($f.Category)|$($f.Rule)"
        if (-not $rules.ContainsKey($k)) { $rules[$k] = [pscustomobject]@{ Category = $f.Category; Rule = $f.Rule; Severity = $f.Severity; Objects = New-Object 'System.Collections.Generic.HashSet[string]'; Remediation = $f.Remediation } }
        $r = $rules[$k]
        if ($rank[[string]$f.Severity] -gt $rank[[string]$r.Severity]) { $r.Severity = $f.Severity }
        [void]$r.Objects.Add("$($f.Scanner)|$($f.Target)")
    }
    $ruleRows = foreach ($r in $rules.Values) {
        [pscustomobject][ordered]@{ Category = $r.Category; Rule = $r.Rule; Severity = $r.Severity; Objects = $r.Objects.Count; Points = $script:ADAuditPoints[[string]$r.Severity]; Remediation = $r.Remediation }
    }
    $ruleRows = @($ruleRows | Sort-Object @{ Expression = { - $rank[[string]$_.Severity] } }, Category, @{ Expression = { - $_.Objects } })

    $cats = foreach ($c in $script:ADAuditCategories) {
        $rs = @($ruleRows | Where-Object { $_.Category -eq $c })
        [pscustomobject][ordered]@{
            Category = $c
            Score    = [math]::Min(100, [int](($rs | Measure-Object -Property Points -Sum).Sum))
            Rules    = $rs.Count
            High     = @($rs | Where-Object Severity -eq 'High').Count
            Medium   = @($rs | Where-Object Severity -eq 'Medium').Count
            Low      = @($rs | Where-Object Severity -eq 'Low').Count
        }
    }
    $cats = @($cats)
    [pscustomobject]@{ Overall = [int](($cats | Measure-Object -Property Score -Maximum).Maximum); Categories = $cats; Rules = $ruleRows }
}
