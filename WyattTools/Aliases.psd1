# Aliases for commands that are not WyattTools functions (built-in cmdlets, external tools).
# Category -> @{ alias = command }. Loaded and exported by WyattTools.psm1 and listed by `tools`.
# Aliases for WyattTools functions stay in that function's own file (e.g. gir, laps).
# Every alias here must also be added to AliasesToExport in WyattTools.psd1.
@{
    Formatting = @{
        table = 'Format-Table'
    }
}
