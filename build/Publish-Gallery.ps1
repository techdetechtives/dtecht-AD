#Requires -Version 5.1
<#
.SYNOPSIS
    Publishes the dtecht-AD module (dist/dtecht-AD) to the PowerShell Gallery.

.DESCRIPTION
    Runs every check first and stops on the first failure:
      1. on branch main with a clean working tree (when git is available)
      2. dist/ is up to date with the sources        (build/Build-Package.ps1 -Check)
      3. read-only guard passes                       (tests/Test-ReadOnly.ps1)
      4. module manifest is valid                     (Test-ModuleManifest)
      5. no PSScriptAnalyzer errors, if it is installed (the Gallery runs the same check)
      6. this version is not already on the Gallery

    Without -Publish it stops after the checks (dry run). The API key is only used for the
    upload; it is never written to disk. Get one at https://www.powershellgallery.com/account/apikeys
    (scope: "Push new packages and package versions", glob pattern: dtecht-AD).

.EXAMPLE
    .\build\Publish-Gallery.ps1                       # checks only
.EXAMPLE
    .\build\Publish-Gallery.ps1 -Publish -ApiKey (Read-Host 'PSGallery API key' -AsSecureString)
.EXAMPLE
    $env:PSGALLERY_API_KEY = '...'; .\build\Publish-Gallery.ps1 -Publish
#>
[CmdletBinding()]
param(
    [switch]$Publish,
    [securestring]$ApiKey,
    [string]$Repository = 'PSGallery'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$moduleDir = Join-Path $root 'dist/dtecht-AD'
$psExe = $(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' })
function Step([string]$Text) { Write-Host "[*] $Text" }
function Ok([string]$Text) { Write-Host "[+] $Text" -ForegroundColor Green }
function Stop-Publish([string]$Text) { Write-Host "[!] $Text" -ForegroundColor Red; exit 1 }

# 1. git state
if (Get-Command git -ErrorAction SilentlyContinue) {
    Push-Location $root
    try {
        $branch = (git rev-parse --abbrev-ref HEAD).Trim()
        $dirty = git status --porcelain
        if ($branch -ne 'main') { Stop-Publish "On branch '$branch'. Publish from main after merging." }
        if ($dirty) { Stop-Publish 'Working tree has uncommitted changes.' }
        Ok "git: main, clean ($((git rev-parse --short HEAD).Trim()))"
    }
    finally { Pop-Location }
}

# 2-3. build up to date + read-only guard
Step 'Checking dist/ is up to date'
& $psExe -NoProfile -File (Join-Path $root 'build/Build-Package.ps1') -Check
if ($LASTEXITCODE -ne 0) { Stop-Publish 'dist/ is stale. Run build/Build-Package.ps1 and commit.' }
Step 'Running read-only guard'
& $psExe -NoProfile -File (Join-Path $root 'tests/Test-ReadOnly.ps1')
if ($LASTEXITCODE -ne 0) { Stop-Publish 'Read-only guard failed.' }

# 4. manifest
$manifest = Test-ModuleManifest -Path (Join-Path $moduleDir 'dtecht-AD.psd1')
$version = $manifest.Version.ToString()
Ok "Manifest: $($manifest.Name) $version, exports $(@($manifest.ExportedCommands.Keys) -join ', ')"

# 5. PSScriptAnalyzer (Gallery blocks on Error severity)
if (Get-Module -ListAvailable PSScriptAnalyzer) {
    Step 'Running PSScriptAnalyzer'
    $issues = @(Invoke-ScriptAnalyzer -Path $moduleDir -Recurse -Severity Error -Settings (Join-Path $root 'PSScriptAnalyzerSettings.psd1'))
    if ($issues) { $issues | Format-Table ScriptName, Line, RuleName, Message -AutoSize | Out-Host; Stop-Publish "$($issues.Count) PSScriptAnalyzer error(s)." }
    Ok 'PSScriptAnalyzer: no errors'
}
else { Write-Warning 'PSScriptAnalyzer not installed (Install-Module PSScriptAnalyzer); the Gallery will run it on upload.' }

# 6. version not already published
$usePsrg = [bool](Get-Command Publish-PSResource -ErrorAction SilentlyContinue)
$existing = $null
$reached = $true
try {
    if ($usePsrg) { $existing = Find-PSResource -Name 'dtecht-AD' -Repository $Repository -ErrorAction Stop }
    else { $existing = Find-Module -Name 'dtecht-AD' -Repository $Repository -ErrorAction Stop }
}
catch {
    # "not found" means first publish; anything else (proxy, TLS, DNS) means we don't know
    if ($_.Exception.Message -notmatch 'could not be found|No match was found|not found') {
        if ($Publish) { Stop-Publish "Could not reach $Repository to check existing versions: $($_.Exception.Message)" }
        Write-Warning "Could not reach $Repository to check existing versions: $($_.Exception.Message)"
        $reached = $false
    }
}
if ($existing) {
    if ([version]$existing.Version -ge [version]$version) { Stop-Publish "Gallery already has dtecht-AD $($existing.Version). Bump the version in Invoke-ADAudit.ps1 (`$meta.Version), rebuild and commit." }
    Ok "Gallery has $($existing.Version) (author: $($existing.Author)); publishing $version"
}
elseif ($reached) { Ok "dtecht-AD is not on $Repository yet (first publish; the name will be registered to your account)" }

if (-not $Publish) { Ok "Dry run complete. Re-run with -Publish to upload dtecht-AD $version."; exit 0 }

# Upload
if (-not $ApiKey -and $env:PSGALLERY_API_KEY) { $ApiKey = ConvertTo-SecureString $env:PSGALLERY_API_KEY -AsPlainText -Force }
if (-not $ApiKey) { $ApiKey = Read-Host 'PowerShell Gallery API key' -AsSecureString }
$plain = [System.Net.NetworkCredential]::new('', $ApiKey).Password
try {
    Step "Publishing dtecht-AD $version to $Repository"
    if ($usePsrg) { Publish-PSResource -Path $moduleDir -Repository $Repository -ApiKey $plain }
    else { Publish-Module -Path $moduleDir -Repository $Repository -NuGetApiKey $plain }
}
finally { $plain = $null }
Ok "Published. Install with: Install-Module dtecht-AD -Scope CurrentUser   (listing: https://www.powershellgallery.com/packages/dtecht-AD/$version)"
