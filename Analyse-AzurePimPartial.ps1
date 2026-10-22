#requires -Version 7.0
<#
.SYNOPSIS
    Offline, streaming analysis of Get-AzurePimPolicyTree-v4.ps1's partial JSONL journal.
    v2 fixes progress calculations for input journals larger than 2 GB.
.DESCRIPTION
    Does not sign in to Azure or make API requests. Reads one JSONL record at a time,
    with FileShare.ReadWrite, so it can analyse an unfinished journal while the
    original collector is still running. Never loads the 3+ GB journal into memory.

    Outputs smaller policy settings, role configuration patterns, candidate review
    findings and scan coverage. Findings are policy configuration observations,
    NOT proof of exploitable access or of actual active assignments.

    IMPORTANT: Scope repetition is expected. Azure-resource PIM policy settings
    are independent at each scope. Only exact repetitions of the same policy ID
    for the same role and scope are skipped.
.EXAMPLE
    ./Analyse-AzurePimPartial.ps1 -JsonlPath 'C:\reports\AzurePim_..._policies.partial.jsonl'
.EXAMPLE
    ./Analyse-AzurePimPartial.ps1 -JsonlPath 'C:\reports\AzurePim_..._policies.partial.jsonl' -OnlyHigherScopes
.EXAMPLE
    ./Analyse-AzurePimPartial.ps1 -JsonlPath 'C:\reports\AzurePim_..._policies.partial.jsonl' -MaxRecords 10000
.NOTES
    PowerShell 7. No Az modules, Python, Azure permissions or network access required.
    Run from a SECOND PowerShell window if collection is still active.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $JsonlPath,
    [string] $OutputDirectory,
    [ValidateRange(1,24)][double] $MaxActivationHours = 8,
    [ValidateRange(0,2147483647)][int] $MaxRecords = 0,
    [switch] $OnlyHigherScopes
)

$ErrorActionPreference = 'Stop'
$src = Get-Item -LiteralPath $JsonlPath -ErrorAction Stop
if ($src.PSIsContainer) { throw 'JsonlPath must be a file.' }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $src.DirectoryName ('PimAnalysis_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
[void] (New-Item -ItemType Directory -Path $OutputDirectory -Force)
$destination = (Resolve-Path -LiteralPath $OutputDirectory).Path

function Write-CsvRow {
    param([System.IO.StreamWriter] $Writer, [object[]] $Values)
    $encoded = [string[]]::new($Values.Length)
    for ($i = 0; $i -lt $Values.Length; $i++) {
        $value = if ($null -eq $Values[$i]) { '' } else { [string] $Values[$i] }
        $encoded[$i] = '"' + $value.Replace('"', '""') + '"'
    }
    $Writer.WriteLine([string]::Join(',', $encoded))
}
function Bool-Value {
    param($Value)
    if ($null -eq $Value) { return 'Unknown' }
    if ($Value -is [bool]) { if ($Value) { return 'Yes' } else { return 'No' } }
    $s = [string] $Value
    if ($s -ieq 'true') { return 'Yes' }
    if ($s -ieq 'false') { return 'No' }
    return 'Unknown'
}
function Duration-Hours {
    param([string] $Duration)
    if ([string]::IsNullOrWhiteSpace($Duration)) { return $null }
    try { return [math]::Round([System.Xml.XmlConvert]::ToTimeSpan($Duration).TotalHours, 3) }
    catch { return $null }
}
function Read-CsvSnapshot {
    param([string] $Path)
    if (-not [IO.File]::Exists($Path)) { return @() }
    # A live file may be mid-append. The last incomplete CSV row is ignored.
    try {
        $file = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $r = [IO.StreamReader]::new($file, [Text.Encoding]::UTF8)
            try { $content = $r.ReadToEnd() } finally { $r.Dispose() }
        }
        finally { $file.Dispose() }
        if ([string]::IsNullOrWhiteSpace($content)) { return @() }
        if (-not $content.EndsWith("`n")) {
            $break = $content.LastIndexOf("`n")
            if ($break -lt 0) { return @() }
            $content = $content.Substring(0, $break + 1)
        }
        return @($content | ConvertFrom-Csv)
    }
    catch {
        Write-Warning "Could not snapshot $Path : $($_.Exception.Message)"
        return @()
    }
}

# Role IDs documented in Microsoft's Azure built-in roles reference.
$roleNames = @{
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
    'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
    'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
    'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
}
$criticalRoles = @{
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = $true
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = $true
    'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = $true
}
$elevatedRoles = @{'b24988ac-6180-42a0-ab88-20f7382dd24c' = $true}

$seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$scopes = @{}
$configs = @{}
$roleVariants = @{}
$roleKindCounts = @{}
$roleKindVariants = @{}
$roles = @{}
$records = 0L
$duplicates = 0L
$malformed = 0L
$unmapped = 0L
$missingRules = 0L
$scopeMismatchCount = 0L
$findingsCount = 0L
$findingsBySeverity = @{}
$recordsByKind = @{}
$badLineSamples = [System.Collections.Generic.List[string]]::new()

$settingsPath = Join-Path $destination 'policy_settings.csv'
$findingsPath = Join-Path $destination 'review_findings.csv'
$settingsWriter = [IO.StreamWriter]::new($settingsPath, $false, [Text.UTF8Encoding]::new($true), 65536)
$findingsWriter = [IO.StreamWriter]::new($findingsPath, $false, [Text.UTF8Encoding]::new($true), 65536)

try {
    Write-CsvRow $settingsWriter @(
        'ScopeKind','ScopeName','ScopeId','Role','RoleGuid','Priority','PolicyId',
        'IsOrganisationDefault','LastModified','ActivationMFA','CAContextEnabled',
        'CAContextId','ApprovalRequired','JustificationRequired','TicketRequired',
        'ActivationMaxDuration','ActivationHours','PermanentEligibleAllowed',
        'PermanentActiveAllowed','EligibleMaxDuration','ActiveMaxDuration',
        'Approvers','NotificationRuleCount','RuleCount','ScopeMatch','ConfigurationId'
    )
    Write-CsvRow $findingsWriter @(
        'Severity','Finding','ScopeKind','ScopeName','ScopeId','Role','RoleGuid',
        'Observed','WhyReview','Qualification'
    )

    # Read concurrently with the collector, with no exclusive lock and no copy.
    $stream = $null
    for ($i = 1; $i -le 5; $i++) {
        try {
            $stream = [IO.FileStream]::new($src.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite, 65536)
            break
        }
        catch {
            if ($i -eq 5) { throw }
            Start-Sleep -Milliseconds (250 * $i)
        }
    }
    $startingBytes = $stream.Length
    $sourceStartWriteTime = (Get-Item -LiteralPath $src.FullName).LastWriteTimeUtc
    $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true, 65536)
    try {
        Write-Host "Analysing locally: $($src.FullName)" -ForegroundColor Cyan
        Write-Host ('Starting size: {0:N2} GB. No Azure calls. Output: {1}' -f ($startingBytes / 1GB), $destination)
        $lineNumber = 0L
        while ($null -ne ($line = $reader.ReadLine())) {
            $lineNumber++
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $r = ConvertFrom-Json -InputObject $line -Depth 100 -ErrorAction Stop
            }
            catch {
                $malformed++
                if ($badLineSamples.Count -lt 20) {
                    [void] $badLineSamples.Add("JSONL line $lineNumber : $($_.Exception.Message)")
                }
                continue
            }
            if (-not $r.ScopeId) {
                $malformed++
                if ($badLineSamples.Count -lt 20) { [void] $badLineSamples.Add("JSONL line $lineNumber : missing ScopeId") }
                continue
            }

            $scopeId = ([string]$r.ScopeId).TrimEnd('/')
            $scopeName = [string]$r.ScopeName
            $kind = [string]$r.ScopeKind
            # The v4 collector writes all management-group and subscription
            # policies before writing any resource-group policies.
            if ($OnlyHigherScopes -and $kind -eq 'ResourceGroup') { break }
            $roleGuid = ([string]$r.RoleDefinitionGuid).ToLowerInvariant()
            if (-not $roleGuid -and $r.RoleDefinitionId) {
                $roleGuid = (([string]$r.RoleDefinitionId).TrimEnd('/') -split '/')[-1].ToLowerInvariant()
            }
            if ($roleGuid -and $roleNames.ContainsKey($roleGuid)) { $roleName = $roleNames[$roleGuid] }
            elseif ($roleGuid) { $roleName = $roleGuid }
            else { $roleName = '[Unmapped policy]' }
            $priority = if ($criticalRoles.ContainsKey($roleGuid)) { 'Critical role' }
                elseif ($elevatedRoles.ContainsKey($roleGuid)) { 'Elevated role' }
                else { 'Other/unresolved' }
            $policyId = [string]$r.PolicyId
            if ($policyId -or $roleGuid) {
                $uniqueKey = $scopeId + "|" + $roleGuid + "|" + $policyId
                if (-not $seen.Add($uniqueKey)) { $duplicates++; continue }
            }

            $summary = $r.Summary
            $mfa = Bool-Value $summary.ActivationMFA
            $ca = Bool-Value $summary.ConditionalAccessContextEnabled
            $approval = Bool-Value $summary.ActivationApproval
            $justification = Bool-Value $summary.ActivationJustification
            $ticket = Bool-Value $summary.ActivationTicket
            $activePermanent = Bool-Value $summary.ActivePermanentAllowed
            $eligiblePermanent = Bool-Value $summary.EligiblePermanentAllowed
            $organisationDefault = Bool-Value $r.IsOrganisationDefault
            $duration = [string]$summary.ActivationMaxDuration
            $eligibleDuration = [string]$summary.EligibleMaxDuration
            $activeDuration = [string]$summary.ActiveMaxDuration
            $durationHours = Duration-Hours $duration
            $caContextId = [string]$summary.ConditionalAccessContextId
            $approvers = [string]$summary.ApprovalApprovers
            $notifications = [string]$summary.NotificationRuleCount
            $ruleCount = if ($null -eq $r.Rules) { 0 } else { @($r.Rules).Count }
            if ($ruleCount -eq 0) { $missingRules++ }
            if (-not $roleGuid) { $unmapped++ }
            $scopeMatch = 'Matches or unreported'
            foreach ($reportedScope in @($r.PolicyRaw.properties.scope, $r.AssignmentRaw.properties.scope)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$reportedScope)) {
                    if (-not [string]::Equals($scopeId, ([string]$reportedScope).TrimEnd('/'), [StringComparison]::OrdinalIgnoreCase)) {
                        $scopeMatch = 'MISMATCH'
                    }
                }
            }
            if ($scopeMatch -eq 'MISMATCH') { $scopeMismatchCount++ }

            # Compare configurations without assuming settings are inherited.
            # Configuration identifiers only describe the captured rule summary.
            $fingerprint = @(
                $mfa, $ca, $caContextId, $approval, $justification, $ticket,
                $duration, $activePermanent, $eligiblePermanent, $activeDuration,
                $eligibleDuration, $notifications
            ) -join '|'
            if (-not $configs.ContainsKey($fingerprint)) {
                $newId = 'C{0:D5}' -f ($configs.Count + 1)
                $configs[$fingerprint] = [pscustomobject]@{
                    Id = $newId; Count = 0L; MFA = $mfa; CA = $ca;
                    Approval = $approval; Justification = $justification;
                    ActivationDuration = $duration; ActivePermanent = $activePermanent;
                    EligiblePermanent = $eligiblePermanent; Notifications = $notifications
                }
            }
            $configuration = $configs[$fingerprint]
            $configuration.Count++

            $roleKey = if ($roleGuid) { $roleGuid } else { '[Unmapped]' }
            if (-not $roles.ContainsKey($roleKey)) {
                $roles[$roleKey] = [pscustomobject]@{
                    Role = $roleName; Guid = $roleGuid; Priority = $priority;
                    Count = 0L; Variants = @{}
                }
            }
            $roles[$roleKey].Count++
            $roles[$roleKey].Variants[$configuration.Id] = $true
            # Compare like with like: variation at resource-group scope may be
            # entirely intentional relative to management-group scope.
            $roleKindKey = $roleKey + '|' + $kind
            if (-not $roleKindCounts.ContainsKey($roleKindKey)) {
                $roleKindCounts[$roleKindKey] = 0L
                $roleKindVariants[$roleKindKey] = @{}
            }
            $roleKindCounts[$roleKindKey]++
            $roleKindVariants[$roleKindKey][$configuration.Id] = $true
            $variantKey = $roleKindKey + '|' + $configuration.Id
            if (-not $roleVariants.ContainsKey($variantKey)) {
                $roleVariants[$variantKey] = [pscustomobject]@{
                    RoleKey = $roleKey; RoleKindKey = $roleKindKey; ScopeKind = $kind;
                    Configuration = $configuration; Count = 0L; ExampleScope = $scopeId
                }
            }
            $roleVariants[$variantKey].Count++
            if (-not $scopes.ContainsKey($scopeId)) {
                $scopes[$scopeId] = [pscustomobject]@{
                    Id = $scopeId; Name = $scopeName; Kind = $kind;
                    Count = 0L; Unmapped = 0L; IncompleteRules = 0L
                }
            }
            $scopes[$scopeId].Count++
            if (-not $roleGuid) { $scopes[$scopeId].Unmapped++ }
            if ($ruleCount -eq 0) { $scopes[$scopeId].IncompleteRules++ }
            if (-not $recordsByKind.ContainsKey($kind)) { $recordsByKind[$kind] = 0L }
            $recordsByKind[$kind]++
            $records++

            Write-CsvRow $settingsWriter @(
                $kind,$scopeName,$scopeId,$roleName,$roleGuid,$priority,$policyId,
                $organisationDefault,$r.LastModified,$mfa,$ca,$caContextId,
                $approval,$justification,$ticket,$duration,$durationHours,
                $eligiblePermanent,$activePermanent,$eligibleDuration,$activeDuration,
                $approvers,$notifications,$ruleCount,$scopeMatch,$configuration.Id
            )

            # Candidate review findings are restricted to recognisable privileged
            # built-in roles, to avoid thousands of false positives for Reader.
            # Organisational Conditional Access and actual assignments are NOT
            # collected here. Findings are not declarations of noncompliance.
            $candidateFindings = [System.Collections.Generic.List[object]]::new()
            if ($scopeMatch -eq 'MISMATCH') {
                [void]$candidateFindings.Add(@('Data quality','Policy scope mismatch','Source policy/assignment scope differs from report ScopeId','Verify the collected record before relying on scope-specific conclusions'))
            }
            if ($priority -ne 'Other/unresolved' -and $scopeMatch -ne 'MISMATCH') {
                if ($ruleCount -eq 0) {
                    [void]$candidateFindings.Add(@('Data quality','Missing policy rules','Rules count = 0','Settings cannot be assessed from this record'))
                }
                else {
                    if ($mfa -eq 'No' -and $ca -eq 'No') {
                        $severity = if ($priority -eq 'Critical role') { 'High review' } else { 'Review' }
                        [void]$candidateFindings.Add(@($severity,'No explicit PIM activation step-up','ActivationMFA=No; CAContext=No','Separate Conditional Access might still enforce authentication'))
                    }
                    if ($activePermanent -eq 'Yes') {
                        $severity = if ($priority -eq 'Critical role') { 'High review' } else { 'Review' }
                        [void]$candidateFindings.Add(@($severity,'Permanent active assignments permitted','ActivePermanentAllowed=Yes','Policy permits them; this does not establish that any exist'))
                    }
                    if ($priority -eq 'Critical role' -and $approval -eq 'No') {
                        [void]$candidateFindings.Add(@('Review','Activation approval not required','ApprovalRequired=No','Approval may be optional under the organisation risk model'))
                    }
                    if ($null -ne $durationHours -and $durationHours -gt $MaxActivationHours) {
                        [void]$candidateFindings.Add(@('Review','Long activation allowance',"Maximum=$duration ($durationHours hours)","Threshold configured for this analysis: $MaxActivationHours hours"))
                    }
                    if ($approval -eq 'Yes' -and [string]::IsNullOrWhiteSpace($approvers)) {
                        [void]$candidateFindings.Add(@('Review','Approval required; no approver shown','ApprovalRequired=Yes; Approvers blank','Check raw approval stages; extraction may be incomplete'))
                    }
                }
            }
            foreach ($f in $candidateFindings) {
                Write-CsvRow $findingsWriter @(
                    $f[0],$f[1],$kind,$scopeName,$scopeId,$roleName,$roleGuid,
                    $f[2],$f[3],
                    'A PIM setting is not proof of an actual eligible/active assignment or its effective access'
                )
                $findingsCount++
                if (-not $findingsBySeverity.ContainsKey([string]$f[0])) { $findingsBySeverity[[string]$f[0]] = 0L }
                $findingsBySeverity[[string]$f[0]]++
            }

            if ($records % 5000 -eq 0) {
                $settingsWriter.Flush()
                $findingsWriter.Flush()
                Write-Host ("Processed {0:N0} distinct policy records across {1:N0} scopes; findings for review: {2:N0}" -f $records,$scopes.Count,$findingsCount)
                # Both FileStream.Position and Length are Int64. With a journal
                # larger than 2 GB, [math]::Max(1, $startingBytes) can select
                # the Int32 overload and throw. Use Double arithmetic, with an
                # explicit zero-length guard. This is an approximate snapshot
                # progress value (StreamReader buffers data).
                $progressPct = 0
                if ($startingBytes -gt 0) {
                    $progressPct = [int][math]::Min(99.0, (100.0 * [double]$stream.Position / [double]$startingBytes))
                }
                Write-Progress -Activity 'Offline PIM policy analysis' -Status "$records records analysed" -PercentComplete $progressPct
            }
            if ($MaxRecords -gt 0 -and $records -ge $MaxRecords) { break }
        }
    }
    finally { $reader.Dispose() }
}
finally {
    $settingsWriter.Dispose()
    $findingsWriter.Dispose()
    Write-Progress -Activity 'Offline PIM policy analysis' -Completed
}

# Write compact aggregate reports only after streaming the large JSONL file.
$patternsPath = Join-Path $destination 'role_configuration_patterns.csv'
$patternsWriter = [IO.StreamWriter]::new($patternsPath, $false, [Text.UTF8Encoding]::new($true))
try {
    Write-CsvRow $patternsWriter @('Role','RoleGuid','Priority','ScopeKind','RoleScopeKindRecords','DistinctConfigurationsForRoleAndScopeKind','ConfigurationId',
        'RecordsWithConfiguration','ShareOfRolePercent','ExampleScope','ActivationMFA','CAContextEnabled',
        'ApprovalRequired','JustificationRequired','ActivationMaxDuration','PermanentActiveAllowed',
        'PermanentEligibleAllowed','NotificationRuleCount','MinorityConfiguration')
    $largestByRole = @{}
    foreach ($v in $roleVariants.Values) {
        if (-not $largestByRole.ContainsKey($v.RoleKindKey) -or $v.Count -gt $largestByRole[$v.RoleKindKey]) {
            $largestByRole[$v.RoleKindKey] = $v.Count
        }
    }
    foreach ($v in @($roleVariants.Values | Sort-Object { $_.RoleKindKey }, { -$_.Count })) {
        $role = $roles[$v.RoleKey]
        $largest = $largestByRole[$v.RoleKindKey]
        $kindRecords = $roleKindCounts[$v.RoleKindKey]
        $pct = if ($kindRecords -gt 0) { [math]::Round(100.0 * [double]$v.Count / [double]$kindRecords, 2) } else { 0.0 }
        $c = $v.Configuration
        Write-CsvRow $patternsWriter @(
            $role.Role,$role.Guid,$role.Priority,$v.ScopeKind,$kindRecords,$roleKindVariants[$v.RoleKindKey].Count,$c.Id,
            $v.Count,$pct,$v.ExampleScope,$c.MFA,$c.CA,$c.Approval,$c.Justification,
            $c.ActivationDuration,$c.ActivePermanent,$c.EligiblePermanent,$c.Notifications,
            $(if ($v.Count -lt $largest) { 'Yes' } else { 'No' })
        )
    }
}
finally { $patternsWriter.Dispose() }

# Compare the policy journal with the live scope journal. These may be sampled at
# slightly different moments when the collector is still running.
$prefix = $src.FullName -replace '_policies\.partial\.jsonl$', ''
$scopeRows = @(Read-CsvSnapshot "${prefix}_scopes.live.csv")
$requestRows = @(Read-CsvSnapshot "${prefix}_requests.live.csv")
$errorRows = @(Read-CsvSnapshot "${prefix}_errors.live.csv")
$loggedScopes = @{}
foreach ($s in $scopeRows) { if ($s.ScopeId) { $loggedScopes[[string]$s.ScopeId] = $s } }
$scopeIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($id in $scopes.Keys) { [void]$scopeIds.Add([string]$id) }
foreach ($id in $loggedScopes.Keys) { [void]$scopeIds.Add([string]$id) }
$coverageWriter = [IO.StreamWriter]::new((Join-Path $destination 'scope_coverage.csv'), $false, [Text.UTF8Encoding]::new($true))
try {
    Write-CsvRow $coverageWriter @('ScopeKind','ScopeName','ScopeId','CollectorStatus','PoliciesInJournal','PoliciesInCollectorStatus',
        'Difference','UnmappedPoliciesInJournal','MissingRulePayloadsInJournal','CoverageNote')
    foreach ($id in @($scopeIds | Sort-Object)) {
        $local = $scopes[$id]
        $logged = $loggedScopes[$id]
        $observed = if ($null -eq $local) { 0L } else { [long]$local.Count }
        $collectorCount = if ($null -ne $logged -and [string]$logged.PolicyRecords -match '^\d+$') { [long]$logged.PolicyRecords } else { $null }
        $difference = if ($null -eq $collectorCount) { '' } else { [string]($observed - $collectorCount) }
        $note = if ($null -eq $logged) { 'No completed collector status at capture time' }
            elseif ($difference -ne '' -and [long]$difference -ne 0) { 'Counts differ: scan may still be running or checkpoint incomplete' }
            else { 'Status available; check failed/partial scopes separately' }
        Write-CsvRow $coverageWriter @(
            $(if ($local) { $local.Kind } else { $logged.ScopeKind }),
            $(if ($local) { $local.Name } else { '' }),
            $id,$logged.Status,$observed,$collectorCount,$difference,
            $(if ($local) { $local.Unmapped } else { 0 }),
            $(if ($local) { $local.IncompleteRules } else { 0 }),$note
        )
    }
}
finally { $coverageWriter.Dispose() }

$listedSubscriptions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$discoveredResourceGroups = 0L
$failedRequests = 0L
foreach ($request in $requestRows) {
    if ($request.Result -eq 'FAILED') { $failedRequests++ }
    if ([string]$request.Path -match '(?i)/subscriptions/([^/?]+)/resourceGroups\?') {
        [void]$listedSubscriptions.Add($Matches[1])
        if ($request.Result -eq 'OK' -and [string]$request.ItemCount -match '^\d+$') {
            $discoveredResourceGroups += [long]$request.ItemCount
        }
    }
}
$kindLines = @($recordsByKind.GetEnumerator() | Sort-Object Name | ForEach-Object { "  $($_.Key): $($_.Value) policy records" })
$severityLines = @($findingsBySeverity.GetEnumerator() | Sort-Object Name | ForEach-Object { "  $($_.Key): $($_.Value) findings" })
$rolesWithVariations = @($roles.Values | Where-Object { $_.Variants.Count -gt 1 }).Count
$roleKindGroupsWithVariations = @($roleKindVariants.Values | Where-Object { $_.Count -gt 1 }).Count
$privilegedInfo = @($roles.Values | Where-Object { $_.Priority -ne 'Other/unresolved' } | Sort-Object Role)
$knownCompletedResourceGroups = @($loggedScopes.Values | Where-Object { $_.ScopeKind -eq 'ResourceGroup' }).Count
$knownSubscriptions = @($loggedScopes.Values | Where-Object { $_.ScopeKind -eq 'Subscription' }).Count
$sourceEndSize = (Get-Item -LiteralPath $src.FullName).Length
$overview = @(
    'OFFLINE AZURE PIM POLICY ANALYSIS'
    "Captured from: $($src.FullName)"
    "Generated at: $(Get-Date -Format o)"
    "Journal size when opened (GB): $([math]::Round($startingBytes/1GB,3))"
    "Journal size at end of analysis (GB): $([math]::Round($sourceEndSize/1GB,3))"
    "Sample limit: $(if ($MaxRecords -gt 0) { $MaxRecords } else { 'No limit' })"
    "Restricted to management group and subscription scopes: $([bool]$OnlyHigherScopes)"
    "Valid distinct policy records: $records"
    "Scopes found in those records: $($scopes.Count)"
    "Role identifiers found: $($roles.Count)"
    "Configuration signatures: $($configs.Count)"
    "Roles with multiple observed configurations (across all scope kinds): $rolesWithVariations"
    "Role + scope-kind groups with multiple configurations: $roleKindGroupsWithVariations"
    "Exact duplicate scope+role+policy records skipped: $duplicates"
    "Malformed/incomplete JSONL lines skipped: $malformed"
    "Records without a mapped role GUID: $unmapped"
    "Records without rule payloads: $missingRules"
    "Records with source-scope mismatch: $scopeMismatchCount"
    "Candidate findings: $findingsCount"
    ''
    'RECORD COUNTS BY SCOPE KIND'
) + $kindLines + @(
    ''
    'FINDINGS BY SEVERITY'
) + $severityLines + @(
    ''
    'PRIVILEGED ROLE COVERAGE IN JOURNAL'
) + @($privilegedInfo | ForEach-Object { "  $($_.Role): $($_.Count) policy records; variants $($_.Variants.Count)" }) + @(
    ''
    'LIVE SCAN COVERAGE (may be newer than the JSONL snapshot)'
    "  Management groups logged: $(@($loggedScopes.Values | Where-Object ScopeKind -eq 'ManagementGroup').Count)"
    "  Subscriptions logged: $knownSubscriptions"
    "  Resource groups logged: $knownCompletedResourceGroups"
    "  Resource groups discovered in listed subscriptions: at least $discoveredResourceGroups"
    "  Subscriptions with resource group listing requests: $($listedSubscriptions.Count) of $knownSubscriptions"
    "  ARM requests failed (request journal): $failedRequests"
    "  Collector errors journal rows: $($errorRows.Count)"
    ''
    'HOW TO INTERPRET'
    '1. Independent role settings at separate Azure scopes can legitimately be identical.'
    '2. role_configuration_patterns.csv compares configurations of the same role AND scope kind.'
    '3. review_findings.csv lists candidate checks for selected privileged built-in roles.'
    '4. No finding proves an active permanent assignment or lack of effective Conditional Access.'
    '5. Unknown rules, unmatched scopes and unscanned scopes are not a clean bill of health.'
    '6. Exact parent management group to child subscription links cannot be reconstructed from this JSONL alone.'
    '7. Role names for unfamiliar/custom GUIDs are unresolved offline.'
    '8. If the collector was running, this is a partial point-in-time extraction, not an exhaustive audit.'
)
if ($badLineSamples.Count) { $overview += ''; $overview += 'FIRST MALFORMED LINES'; $overview += $badLineSamples }
$overviewPath = Join-Path $destination 'overview.txt'
$overview | Set-Content -LiteralPath $overviewPath -Encoding utf8

Write-Host "`nCompleted local analysis in: $destination" -ForegroundColor Green
Write-Host "Policy records analysed: $records; scopes with records: $($scopes.Count); findings: $findingsCount"
Write-Host "Review: overview.txt, review_findings.csv, role_configuration_patterns.csv, scope_coverage.csv"
Write-Host "Detailed settings: policy_settings.csv"
if ($malformed) { Write-Warning "$malformed malformed or partly written JSONL lines skipped; see overview.txt." }
if ($MaxRecords -gt 0 -or $OnlyHigherScopes) { Write-Warning 'This is a restricted/partial analysis. Do not treat missing findings as tenant-wide.' }
