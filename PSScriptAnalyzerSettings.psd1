# PSScriptAnalyzer settings for dtecht-AD (used by build/Publish-Gallery.ps1 and editors).
# The PowerShell Gallery blocks only on Error-severity findings; these warnings are excluded on purpose:
@{
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'                      # console progress output is intended; results go to files
        'PSAvoidUsingEmptyCatchBlock'                # best-effort reads (e.g. optional attributes) fall back silently
        'PSUseShouldProcessForStateChangingFunctions' # New-ADAudit* helpers only build in-memory objects; nothing changes state
        'PSUseSingularNouns'                         # e.g. Get-ADAuditTier0Sids returns a set by design
        'PSReviewUnusedParameter'                    # parameters kept for a stable call signature
    )
}
