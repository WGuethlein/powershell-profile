# PSScriptAnalyzer settings for the WyattTools module.
# Usage: Invoke-ScriptAnalyzer -Path .\WyattTools -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @('PSAvoidUsingWriteHost')
}
