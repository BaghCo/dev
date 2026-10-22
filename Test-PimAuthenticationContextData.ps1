#requires -Version 7.0
<#
.SYNOPSIS
    Diagnose authentication-context results in the Azure PIM analyser output.
.DESCRIPTION
    Offline only. Reads the existing policy_settings.csv and optionally samples
    the original partial JSONL to cross-check the collector's Summary against
    the actual AuthenticationContext_EndUser_Assignment ARM rule.
    Never contacts Azure or Microsoft Graph and never requests consent.
.EXAMPLE
    .\Test-PimAuthenticationContextData.ps1 -PolicySettingsCsv '.\AzurePimReport\PimAnalysis_20261022_093616\policy_settings.csv'
.EXAMPLE
    .\Test-PimAuthenticationContextData.ps1 -PolicySettingsCsv $csv -JsonlPath $journal.FullName -RawRecordsToCheck 2000
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PolicySettingsCsv,
    [string]$JsonlPath,
    [string]$OutputDirectory = (Join-Path (Get-Location).Path 'PimContextCheck'),
    [ValidateRange(1,100000)][int]$RawRecordsToCheck = 1000
)

$ErrorActionPreference = 'Stop'
$csvFile = Get-Item -LiteralPath $PolicySettingsCsv -ErrorAction Stop
if ($csvFile.PSIsContainer) { throw 'PolicySettingsCsv must refer to a file.' }
[void](New-Item -ItemType Directory -Force -Path $OutputDirectory)
$out = (Resolve-Path -LiteralPath $OutputDirectory).Path

$counts = [ordered]@{ Yes = [long]0; No = [long]0; Unknown = [long]0; Other = [long]0 }
$contexts = @{}
$rows = [long]0
$withContextId = [long]0
$rowsWithoutRules = [long]0
$defaults = [ordered]@{ Yes = [long]0; No = [long]0; Unknown = [long]0 }
$first = $true

Import-Csv -LiteralPath $csvFile.FullName | ForEach-Object {
    $row = $_
    if ($first) {
        $columns = @($row.PSObject.Properties.Name)
        $missing = @('CAContextEnabled','CAContextId','RuleCount','IsOrganisationDefault') | Where-Object { $_ -notin $columns }
        if ($missing) { throw "Incorrect CSV schema. Missing: $($missing -join ', ')" }
        $first = $false
    }
    $rows++
    $flag = ([string]$row.CAContextEnabled).Trim().ToLowerInvariant()
    switch ($flag) {
        { $_ -in @('yes','true','1') } { $counts.Yes++; break }
        { $_ -in @('no','false','0') } { $counts.No++; break }
        { $_ -in @('unknown','') } { $counts.Unknown++; break }
        default { $counts.Other++ }
    }
    $ctx = ([string]$row.CAContextId).Trim()
    if ($ctx) {
        $withContextId++
        if (-not $contexts.ContainsKey($ctx)) { $contexts[$ctx] = [long]0 }
        $contexts[$ctx]++
    }
    if ([string]$row.RuleCount -eq '0') { $rowsWithoutRules++ }
    $def = ([string]$row.IsOrganisationDefault).Trim().ToLowerInvariant()
    if ($def -in @('yes','true')) { $defaults.Yes++ }
    elseif ($def -in @('no','false')) { $defaults.No++ }
    else { $defaults.Unknown++ }
}

$rawCount = [long]0
$rawRulePresent = [long]0
$rawEnabled = [long]0
$rawDisabled = [long]0
$rawMissing = [long]0
$rawMismatches = [long]0
$examples = [System.Collections.Generic.List[object]]::new()
if ($JsonlPath) {
    $jsonlFile = Get-Item -LiteralPath $JsonlPath -ErrorAction Stop
    if ($jsonlFile.PSIsContainer) { throw 'JsonlPath must refer to a file.' }
    $stream = [IO.FileStream]::new($jsonlFile.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        $reader = [IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true,65536)
        try {
            while ($rawCount -lt $RawRecordsToCheck -and $null -ne ($line = $reader.ReadLine())) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                try { $r = ConvertFrom-Json -InputObject $line -Depth 100 -ErrorAction Stop }
                catch { Write-Warning 'A malformed or incomplete JSONL line was skipped'; continue }
                $rawCount++
                $rawRule = @($r.Rules | Where-Object { $null -ne $_ -and $_.id -ieq 'AuthenticationContext_EndUser_Assignment' } | Select-Object -First 1)
                $rule = if ($rawRule.Count -gt 0) { $rawRule[0] } else { $null }
                $rawState = 'Missing'
                $rawId = ''
                if ($null -ne $rule) {
                    $rawRulePresent++
                    $rawId = [string]$rule.claimValue
                    if ($rule.isEnabled -is [bool]) {
                        if ($rule.isEnabled) { $rawState = 'Yes'; $rawEnabled++ }
                        else { $rawState = 'No'; $rawDisabled++ }
                    }
                    else { $rawState = 'Unknown' }
                }
                else { $rawMissing++ }
                $summaryState = 'Unknown'
                if ($r.Summary.ConditionalAccessContextEnabled -is [bool]) {
                    if ($r.Summary.ConditionalAccessContextEnabled) { $summaryState = 'Yes' }
                    else { $summaryState = 'No' }
                }
                $summaryId = [string]$r.Summary.ConditionalAccessContextId
                $mismatch = ($rawState -ne $summaryState -or $rawId -ne $summaryId)
                if ($mismatch) { $rawMismatches++ }
                if ($examples.Count -lt 50 -and ($mismatch -or $rawState -eq 'Yes' -or $examples.Count -lt 5)) {
                    [void]$examples.Add([pscustomobject]@{
                        ScopeKind = [string]$r.ScopeKind
                        ScopeName = [string]$r.ScopeName
                        RoleGuid = [string]$r.RoleDefinitionGuid
                        RawRule = $rawState
                        RawContextId = $rawId
                        CollectorSummary = $summaryState
                        SummaryContextId = $summaryId
                        Disagrees = $mismatch
                    })
                }
            }
        }
        finally { $reader.Dispose() }
    }
    finally { $stream.Dispose() }
    if ($examples.Count -gt 0) {
        $examples | Export-Csv -LiteralPath (Join-Path $out 'raw_rule_check.csv') -NoTypeInformation -Encoding utf8
    }
}

$summary = [ordered]@{
    CsvPath = $csvFile.FullName
    CsvRecords = $rows
    Enabled = $counts.Yes
    Disabled = $counts.No
    Unknown = $counts.Unknown
    Other = $counts.Other
    ContextIdsPresent = $withContextId
    DistinctContextIds = $contexts.Count
    NoRulePayload = $rowsWithoutRules
    OrganisationDefaultYes = $defaults.Yes
    OrganisationDefaultNo = $defaults.No
    OrganisationDefaultUnknown = $defaults.Unknown
    RawJsonlChecked = $rawCount
    RawRulePresent = $rawRulePresent
    RawEnabled = $rawEnabled
    RawDisabled = $rawDisabled
    RawRuleMissing = $rawMissing
    RawVersusSummaryDisagreements = $rawMismatches
    Limitations = 'The JSONL check is a sample of the first N records only. PIM policy settings do not prove any users have those roles. Separate Conditional Access policies are not evaluated.'
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'authentication_context_diagnosis.json') -Encoding utf8
$summary.GetEnumerator() | ForEach-Object { '{0}: {1}' -f $_.Key,$_.Value } | Set-Content -LiteralPath (Join-Path $out 'authentication_context_diagnosis.txt') -Encoding utf8

Write-Host "Read $rows PIM policy records: enabled=$($counts.Yes), disabled=$($counts.No), unknown=$($counts.Unknown), other=$($counts.Other)." -ForegroundColor Cyan
Write-Host "Context IDs recorded: $withContextId rows, $($contexts.Count) distinct IDs. Policies with zero rules: $rowsWithoutRules."
if ($counts.Yes -eq 0) {
    Write-Host 'No enabled authentication contexts appear in this CSV. An empty context-reference list is expected, not a failed export.' -ForegroundColor Yellow
}
if ($JsonlPath) {
    Write-Host "Checked $rawCount original JSONL records: raw enabled=$rawEnabled, disabled=$rawDisabled, missing rule=$rawMissing, raw/summary disagreements=$rawMismatches."
    if ($rawMismatches -gt 0) { Write-Warning 'The collector summaries disagree with the raw rules. Do not rely on the CSV authentication-context status until this is corrected.' }
}
Write-Host "Saved diagnosis: $out"
