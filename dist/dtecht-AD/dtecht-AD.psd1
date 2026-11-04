@{
    RootModule           = 'dtecht-AD.psm1'
    ModuleVersion        = '1.2.0'
    GUID                 = '6f1c9d2e-3b7a-4e58-9c41-0d2a7be5f913'
    Author               = 'TechDetechtives'
    CompanyName          = 'TechDetechtives'
    Copyright            = '(c) 2026 TechDetechtives. MIT License.'
    Description          = 'Read-only Active Directory security audit: accounts, groups, ACLs/DCSync, GPO audit policy, DC events, host checks, risk score and run-to-run comparison. Nothing is written to AD or scanned hosts.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @('Invoke-DtechtAD')
    AliasesToExport      = @('dtecht-ad')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('ActiveDirectory', 'Security', 'Audit', 'BlueTeam', 'PingCastle', 'DCSync', 'Windows')
            LicenseUri = 'https://github.com/techdetechtives/dtecht-AD/blob/main/LICENSE'
            ProjectUri = 'https://github.com/techdetechtives/dtecht-AD'
        }
    }
}