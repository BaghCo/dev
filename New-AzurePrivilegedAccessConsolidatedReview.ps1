#requires -Version 7.0
<#
.SYNOPSIS
  Re-run the previously used PIM and standing-access checks against saved evidence.
.DESCRIPTION
  OFFLINE: no Azure, Microsoft Graph, PIM portal or administrator privileges.
  Reads the CSVs produced by Get-AzurePimScopeEvidence-v3.ps1 and
  Analyse-AzurePimPartial-v2.ps1. Recalculates the previous PowerShell snippets:
  - active assignment type / member type / end-date distribution
  - direct standing privileges by role and Azure scope
  - current PIM eligibilities, group assignees and eligibility expiry
  - exact-scope-and-role matching to the PIM policy configuration
  - PIM MFA, authentication context, approval, duration and expiry settings
  - management group hierarchy, observed descendant subscriptions and coverage
  Creates NEW Confluence Markdown and evidence CSVs in a timestamped directory.
  Never modifies or deletes the original evidence or previous reports.

  The standing access and PIM eligibility findings are kept separate. RBAC grant
  inheritance is not double-counted. Policies at parent scopes are never assumed
  to govern assignments at child scopes. PIM for Groups, directory-role PIM,
  group membership, Conditional Access and per-resource grants are not covered.
.EXAMPLE
  .\New-AzurePrivilegedAccessConsolidatedReview.ps1 `
    -ScopeAuditDirectory '.\PIMScopeAudit' `
    -PolicySettingsCsv '.\AzurePimReport\PimAnalysis_20261022_093616\policy_settings.csv'
.NOTES
  Requires PowerShell 7. Source files stay in place. Output contains principal IDs
  and role grant scopes. Keep the report within authorised internal storage.
#>
[CmdletBinding()]
param(
    [string] $ScopeAuditDirectory = '.\PIMScopeAudit',
    [Parameter(Mandatory)] [string] $PolicySettingsCsv,
    [string] $AssigneeExpiryCsv,
    [string] $OutputDirectory,
    [ValidateRange(5,300)] [int] $MaxSummaryRows = 30
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-Field {
    param($Record, [string]$Name)
    if ($null -eq $Record) { return '' }
    $item = $Record.PSObject.Properties[$Name]
    if ($null -eq $item -or $null -eq $item.Value) { return '' }
    return [string]$item.Value
}
function Scope-Key {
    param([string]$ScopeId)
    if ([string]::IsNullOrWhiteSpace($ScopeId)) { return '' }
    return $ScopeId.Trim().TrimEnd('/').ToLowerInvariant()
}
function Role-Key {
    param([string]$RoleId)
    if ([string]::IsNullOrWhiteSpace($RoleId)) { return '' }
    return ($RoleId.Trim().TrimEnd('/') -split '/')[-1].ToLowerInvariant()
}
function Policy-Key {
    param([string]$ScopeId,[string]$RoleId)
    return (Scope-Key $ScopeId) + '|' + (Role-Key $RoleId)
}
function Truth-State {
    param([string]$Value)
    switch ($Value.Trim().ToLowerInvariant()) {
        { $_ -in @('yes','true','1') } { return 'Yes' }
        { $_ -in @('no','false','0') } { return 'No' }
        default { return 'Unknown' }
    }
}
function Has-NoExpiry {
    param([string]$EndDateTime)
    return [string]::IsNullOrWhiteSpace($EndDateTime)
}
function Text-Or {
    param($Value,[string]$Fallback = 'Not recorded')
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $Fallback }
    return $s
}
function Md-Cell {
    param($Value)
    $s = Text-Or $Value
    return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('|','\|').Replace("`r",' ').Replace("`n",' ').Replace('`','')
}
function Safe-TreeName {
    param([string]$Value)
    if (-not $Value) { return '(unnamed scope)' }
    return ($Value -replace '[\r\n\t]',' ' -replace '[`\\]','')
}
function Assert-Columns {
    param([object[]]$Rows,[string]$Label,[string[]]$Expected)
    if ($Rows.Count -eq 0) { throw "$Label is empty; cannot establish evidence coverage." }
    $available = @($Rows[0].PSObject.Properties.Name)
    foreach ($column in $Expected) {
        if ($column -notin $available) { throw "$Label is missing column '$column'. Verify the saved CSV corresponds to the previous collector." }
    }
}
function Load-Csv {
    param([string]$Directory,[string]$File,[switch]$Optional)
    $location = Join-Path $Directory $File
    if (-not (Test-Path -LiteralPath $location -PathType Leaf)) {
        if ($Optional) { return @() }
        throw "Required completed evidence file missing: $location. Do not use partial CSVs to certify scan completeness."
    }
    return @(Import-Csv -LiteralPath $location -ErrorAction Stop)
}
function Get-ScopeType {
    param($Entry)
    $kind = Read-Field $Entry 'ScopeKind'
    if (-not $kind) { $kind = Read-Field $Entry 'Kind' }
    if ($kind) { return $kind }
    $id = Read-Field $Entry 'AssignmentScope'
    if ($id -match '(?i)^/providers/Microsoft\.Management/managementGroups/[^/]+$') { return 'ManagementGroup' }
    if ($id -match '(?i)^/subscriptions/[^/]+$') { return 'Subscription' }
    if ($id -match '(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return 'ResourceGroup' }
    return 'Other'
}
function Get-Tier {
    param($Entry)
    $guid = Role-Key (Read-Field $Entry 'RoleGuid')
    if (-not $guid) { $guid = Role-Key (Read-Field $Entry 'RoleDefinitionId') }
    if ($guid -in @('8e3af657-a8ff-443c-a75c-2fe8c4bcb635','18d7d88d-d35e-4fb5-a5c3-7773c20a72d9','f58310d9-a9f6-439a-9e8d-f62e7b41a168')) { return 'Critical' }
    if ($guid -in @('b24988ac-6180-42a0-ab88-20f7382dd24c','00482a5a-887f-4fb3-b363-3b7fe8e74483')) { return 'Elevated' }
    $existing = Read-Field $Entry 'Tier'
    if ($existing -in @('Critical','Elevated','Lower','Unclassified')) { return $existing }
    return 'Unclassified'
}
function Schedule-Key {
    param($Entry)
    $id = Read-Field $Entry 'ScheduleId'
    if ($id) { return $id.ToLowerInvariant() }
    return ('{0}|{1}|{2}|{3}' -f (Read-Field $Entry 'PrincipalId'),(Read-Field $Entry 'RoleGuid'),(Read-Field $Entry 'AssignmentScope'),(Read-Field $Entry 'StartDateTime')).ToLowerInvariant()
}
function Unique-Grants {
    param([object[]]$Rows)
    $hash = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $keep = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Rows) {
        $key = Schedule-Key $r
        if ($hash.Add($key)) { [void]$keep.Add($r) }
    }
    return @($keep.ToArray())
}

$scan = (Resolve-Path -LiteralPath $ScopeAuditDirectory -ErrorAction Stop).Path
$policySource = (Resolve-Path -LiteralPath $PolicySettingsCsv -ErrorAction Stop).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $scan ('ConsolidatedReview_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
if (Test-Path -LiteralPath $OutputDirectory) { throw "Output directory already exists; choose a new directory to avoid overwriting evidence: $OutputDirectory" }
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop)
$output = (Resolve-Path -LiteralPath $OutputDirectory).Path

$eligible = @(Load-Csv $scan 'pim_eligible_assignments.csv')
$active = @(Load-Csv $scan 'pim_active_schedule_instances.csv')
$scopes = @(Load-Csv $scan 'observed_scope_hierarchy.csv')
$status = @(Load-Csv $scan 'scan_status.csv')
$errors = @(Load-Csv $scan 'errors.csv' -Optional)
$optionalRbac = @(Load-Csv $scan 'rbac_current_assignments.csv' -Optional)
Assert-Columns $eligible 'pim_eligible_assignments.csv' @('Role','RoleGuid','PrincipalId','PrincipalType','AssignmentScope','ScheduleId','EndDateTime','Status','MemberType','ScopeKind')
Assert-Columns $active 'pim_active_schedule_instances.csv' @('Role','RoleGuid','PrincipalId','PrincipalType','AssignmentScope','ScheduleId','EndDateTime','Status','MemberType','AssignmentType','ScopeKind')
Assert-Columns $scopes 'observed_scope_hierarchy.csv' @('ScopeId','ScopeName','ParentId','Kind')
Assert-Columns $status 'scan_status.csv' @('ScopeId','Eligible','ActiveSchedule','DirectEligible','DirectActive')

# Never silently equate a missing row or failed scan with an empty Azure scope.
$expectedElig = 0L; $expectedActive = 0L
foreach ($s in $status) {
    $expectedElig += [long](Read-Field $s 'DirectEligible')
    $expectedActive += [long](Read-Field $s 'DirectActive')
}
$completeCountMatch = ($expectedElig -eq $eligible.Count -and $expectedActive -eq $active.Count)
$failedScopes = @($status | Where-Object { (Read-Field $_ 'Eligible') -ne 'OK' -or (Read-Field $_ 'ActiveSchedule') -ne 'OK' })
$scanComplete = ($failedScopes.Count -eq 0 -and $completeCountMatch -and $errors.Count -eq 0)

# Capture the most recent file write time as a label, never as a validated Azure snapshot time.
$files = @('pim_eligible_assignments.csv','pim_active_schedule_instances.csv','observed_scope_hierarchy.csv','scan_status.csv')
$fileStamp = @($files | ForEach-Object { (Get-Item -LiteralPath (Join-Path $scan $_)).LastWriteTimeUtc } | Sort-Object -Descending | Select-Object -First 1)[0]

# Build observed management group / subscription hierarchy.
$nodeIndex = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$children = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($node in $scopes) {
    $key = Scope-Key (Read-Field $node 'ScopeId')
    if (-not $key) { continue }
    if (-not $nodeIndex.ContainsKey($key)) { $nodeIndex.Add($key,$node) }
    $parent = Scope-Key (Read-Field $node 'ParentId')
    if (-not $children.ContainsKey($parent)) { $children.Add($parent,[System.Collections.Generic.List[object]]::new()) }
    [void]$children[$parent].Add($node)
}
function Get-PathLabels {
    param([string]$ScopeId)
    $key = Scope-Key $ScopeId
    $parts = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    while ($key -and $nodeIndex.ContainsKey($key) -and $seen.Add($key)) {
        $node = $nodeIndex[$key]
        $nodeName = Read-Field $node 'ScopeName'
        if (-not $nodeName) { $nodeName = ($key -split '/')[-1] }
        $parts.Insert(0,$nodeName)
        $key = Scope-Key (Read-Field $node 'ParentId')
    }
    if ($parts.Count -eq 0) { return (Text-Or $ScopeId) }
    return ($parts.ToArray() -join ' / ')
}
function Get-ObservedDescendantSubscriptions {
    param([string]$ScopeId)
    $root = Scope-Key $ScopeId
    $count = 0
    foreach ($item in $scopes) {
        if ((Read-Field $item 'Kind') -ne 'Subscription') { continue }
        $cursor = Scope-Key (Read-Field $item 'ParentId')
        $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        while ($cursor -and $visited.Add($cursor) -and $nodeIndex.ContainsKey($cursor)) {
            if ($cursor -eq $root) { $count++; break }
            $cursor = Scope-Key (Read-Field $nodeIndex[$cursor] 'ParentId')
        }
    }
    return $count
}

# Avoid double-counting inherited repeats, but retain separately granted parent and child roles.
$currentEligible = @(Unique-Grants @($eligible | Where-Object { $_.Status -eq 'Current' -and $_.MemberType -ne 'Inherited' }))
$currentActive = @(Unique-Grants @($active | Where-Object { $_.Status -eq 'Current' -and $_.MemberType -ne 'Inherited' }))
$standing = @($currentActive | Where-Object { $_.AssignmentType -eq 'Assigned' -and $_.MemberType -eq 'Direct' -and (Has-NoExpiry $_.EndDateTime) })
$activated = @($currentActive | Where-Object { $_.AssignmentType -eq 'Activated' })
$standingHighBroad = @($standing | Where-Object { (Get-Tier $_) -in @('Critical','Elevated') -and (Get-ScopeType $_) -in @('ManagementGroup','Subscription') } | Sort-Object ScopeKind,Role,AssignmentScope,PrincipalId)
$eligibleHighBroad = @($currentEligible | Where-Object { (Get-Tier $_) -in @('Critical','Elevated') -and (Get-ScopeType $_) -in @('ManagementGroup','Subscription') } | Sort-Object ScopeKind,Role,AssignmentScope)
$withoutEligibleEnd = @($currentEligible | Where-Object { Has-NoExpiry $_.EndDateTime })
$groupEligible = @($currentEligible | Where-Object { $_.PrincipalType -in @('Group','ForeignGroup') })

# The policy inventory can be very large. Stream once, retaining only records
# matching CURRENT ACTUAL eligibilities at their exact Azure grant scope and role.
$wanted = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($g in $currentEligible) { [void]$wanted.Add((Policy-Key (Read-Field $g 'AssignmentScope') (Read-Field $g 'RoleGuid'))) }
$matchingPolicies = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$policyRows = 0L; $policyMfaNo = 0L; $policyMfaYes = 0L; $policyMfaUnknown = 0L
$policyCtxNo = 0L; $policyCtxYes = 0L; $policyCtxUnknown = 0L
$policyRowsMatched = 0L
Write-Host 'Reading previously exported policy configurations offline...' -ForegroundColor Cyan
Import-Csv -LiteralPath $policySource -ErrorAction Stop | ForEach-Object {
    $policyRows++
    switch (Truth-State (Read-Field $_ 'ActivationMFA')) {
        'Yes' { $policyMfaYes++ }
        'No' { $policyMfaNo++ }
        default { $policyMfaUnknown++ }
    }
    switch (Truth-State (Read-Field $_ 'CAContextEnabled')) {
        'Yes' { $policyCtxYes++ }
        'No' { $policyCtxNo++ }
        default { $policyCtxUnknown++ }
    }
    $key = Policy-Key (Read-Field $_ 'ScopeId') (Read-Field $_ 'RoleGuid')
    if ($wanted.Contains($key)) {
        $policyRowsMatched++
        if (-not $matchingPolicies.ContainsKey($key)) { $matchingPolicies.Add($key,[System.Collections.Generic.List[object]]::new()) }
        [void]$matchingPolicies[$key].Add($_)
    }
}
if ($policyRows -eq 0) { throw 'policy_settings.csv contains no rows. Cannot build a configuration assessment.' }

$assigneeNames = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
if (-not $AssigneeExpiryCsv) {
    $possibleNames = Join-Path $scan 'AssigneeExpiryReview\Azure-PIM-Assignee-Expiry-Register.csv'
    if (Test-Path -LiteralPath $possibleNames -PathType Leaf) { $AssigneeExpiryCsv = $possibleNames }
}
if ($AssigneeExpiryCsv) {
    $nameFile = (Resolve-Path -LiteralPath $AssigneeExpiryCsv -ErrorAction Stop).Path
    foreach ($row in @(Import-Csv -LiteralPath $nameFile -ErrorAction Stop)) {
        $schedule = Read-Field $row 'ScheduleId'
        $name = Read-Field $row 'PrincipalName'
        if ($schedule -and $name -and -not $assigneeNames.ContainsKey($schedule)) { $assigneeNames.Add($schedule,$name) }
    }
}
function Get-PolicyMatch {
    param($Grant)
    $key = Policy-Key (Read-Field $Grant 'AssignmentScope') (Read-Field $Grant 'RoleGuid')
    if (-not $matchingPolicies.ContainsKey($key)) { return [pscustomobject]@{ State='Missing'; Policy=$null; PolicyIds='' } }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $distinct = [System.Collections.Generic.List[object]]::new()
    foreach ($candidate in @($matchingPolicies[$key].ToArray())) {
        $signature = @(
            (Read-Field $candidate 'PolicyId'), (Read-Field $candidate 'ActivationMFA'),
            (Read-Field $candidate 'CAContextEnabled'),(Read-Field $candidate 'CAContextId'),
            (Read-Field $candidate 'ApprovalRequired'),(Read-Field $candidate 'JustificationRequired'),
            (Read-Field $candidate 'ActivationMaxDuration'),(Read-Field $candidate 'PermanentEligibleAllowed'),
            (Read-Field $candidate 'EligibleMaxDuration'),(Read-Field $candidate 'PermanentActiveAllowed'),
            (Read-Field $candidate 'ActiveMaxDuration'),(Read-Field $candidate 'ScopeMatch'),(Read-Field $candidate 'RuleCount')
        ) -join '|'
        if ($seen.Add($signature)) { [void]$distinct.Add($candidate) }
    }
    $ids = (@($distinct.ToArray() | ForEach-Object { Read-Field $_ 'PolicyId' } | Sort-Object -Unique) -join '; ')
    if ($distinct.Count -ne 1) { return [pscustomobject]@{ State='Conflicting snapshots'; Policy=$null; PolicyIds=$ids } }
    $one = $distinct[0]
    $rules = 0
    $validRules = [int]::TryParse((Read-Field $one 'RuleCount'),[ref]$rules)
    if ((Read-Field $one 'ScopeMatch') -eq 'MISMATCH' -or -not $validRules -or $rules -le 0) {
        return [pscustomobject]@{ State='Rules or scope unverified'; Policy=$null; PolicyIds=$ids }
    }
    return [pscustomobject]@{ State='Matched'; Policy=$one; PolicyIds=$ids }
}

$eligibilityEvidence = [System.Collections.Generic.List[object]]::new()
foreach ($grant in $currentEligible) {
    $match = Get-PolicyMatch $grant
    $policy = $match.Policy
    $mfa = if ($null -ne $policy) { Truth-State (Read-Field $policy 'ActivationMFA') } else { 'Unknown' }
    $context = if ($null -ne $policy) { Truth-State (Read-Field $policy 'CAContextEnabled') } else { 'Unknown' }
    $approvals = if ($null -ne $policy) { Truth-State (Read-Field $policy 'ApprovalRequired') } else { 'Unknown' }
    $permanentAllowed = if ($null -ne $policy) { Truth-State (Read-Field $policy 'PermanentEligibleAllowed') } else { 'Unknown' }
    $stepup = if ($match.State -ne 'Matched') { 'Not verified' }
        elseif ($mfa -eq 'No' -and $context -eq 'No') { 'No PIM activation MFA or auth. context' }
        elseif ($mfa -eq 'Yes' -or $context -eq 'Yes') { 'Some PIM step-up configured (enforcement unverified)' }
        else { 'Activation protection unclear' }
    $id = Read-Field $grant 'ScheduleId'
    $name = Read-Field $grant 'PrincipalId'
    if ($assigneeNames.ContainsKey($id)) { $name = $assigneeNames[$id] }
    [void]$eligibilityEvidence.Add([pscustomobject][ordered]@{
        RecordType='PIM eligible'; Role=(Read-Field $grant 'Role'); Tier=(Get-Tier $grant)
        ScopeKind=(Get-ScopeType $grant); ScopeName=(Read-Field $grant 'ScopeName')
        GrantScope=(Read-Field $grant 'AssignmentScope'); ScopePath=(Get-PathLabels (Read-Field $grant 'AssignmentScope'))
        ObservedDescendantSubscriptions=(Get-ObservedDescendantSubscriptions (Read-Field $grant 'AssignmentScope'))
        PrincipalName=$name; PrincipalType=(Read-Field $grant 'PrincipalType'); PrincipalId=(Read-Field $grant 'PrincipalId')
        MemberType=(Read-Field $grant 'MemberType'); RoleGuid=(Role-Key (Read-Field $grant 'RoleGuid'))
        ScheduleId=$id; StartDateTime=(Read-Field $grant 'StartDateTime'); EndDateTime=(Read-Field $grant 'EndDateTime')
        ExpiryDescription=$(if (Has-NoExpiry (Read-Field $grant 'EndDateTime')) { 'No eligibility end date returned' } else { 'Time-bound eligibility' })
        PolicyMatch=$match.State; PolicyId=$match.PolicyIds
        ActivationMFA=$mfa; CAContextEnabled=$context; CAContextId=(Read-Field $policy 'CAContextId')
        ApprovalRequired=$approvals; JustificationRequired=(Truth-State (Read-Field $policy 'JustificationRequired'))
        PermanentEligibleAllowed=$permanentAllowed; EligibleMaxDuration=(Read-Field $policy 'EligibleMaxDuration')
        ActivationMaxDuration=(Read-Field $policy 'ActivationMaxDuration'); PermanentActiveAllowed=(Truth-State (Read-Field $policy 'PermanentActiveAllowed'))
        ActivationSafeguard=$stepup; Condition=(Read-Field $grant 'Condition')
    })
}
$eligResults = @($eligibilityEvidence.ToArray())
$matchedElig = @($eligResults | Where-Object PolicyMatch -eq 'Matched')
$unmatchedElig = @($eligResults | Where-Object PolicyMatch -ne 'Matched')
$noStepUp = @($matchedElig | Where-Object ActivationSafeguard -eq 'No PIM activation MFA or auth. context')
$noEndPermitted = @($matchedElig | Where-Object { $_.PermanentEligibleAllowed -eq 'Yes' -and (Has-NoExpiry $_.EndDateTime) })
$noEndPolicyRequires = @($matchedElig | Where-Object { $_.PermanentEligibleAllowed -eq 'No' -and (Has-NoExpiry $_.EndDateTime) })

# Export all current active + eligible records so every number is inspectable.
$allEvidence = [System.Collections.Generic.List[object]]::new()
foreach ($row in $eligResults) { [void]$allEvidence.Add($row) }
foreach ($grant in $currentActive) {
    [void]$allEvidence.Add([pscustomobject][ordered]@{
        RecordType=('Active schedule: '+(Read-Field $grant 'AssignmentType')); Role=(Read-Field $grant 'Role'); Tier=(Get-Tier $grant)
        ScopeKind=(Get-ScopeType $grant); ScopeName=(Read-Field $grant 'ScopeName')
        GrantScope=(Read-Field $grant 'AssignmentScope'); ScopePath=(Get-PathLabels (Read-Field $grant 'AssignmentScope'))
        ObservedDescendantSubscriptions=(Get-ObservedDescendantSubscriptions (Read-Field $grant 'AssignmentScope'))
        PrincipalName=''; PrincipalType=(Read-Field $grant 'PrincipalType'); PrincipalId=(Read-Field $grant 'PrincipalId')
        MemberType=(Read-Field $grant 'MemberType'); RoleGuid=(Role-Key (Read-Field $grant 'RoleGuid'))
        ScheduleId=(Read-Field $grant 'ScheduleId'); StartDateTime=(Read-Field $grant 'StartDateTime'); EndDateTime=(Read-Field $grant 'EndDateTime')
        ExpiryDescription=$(if (Has-NoExpiry (Read-Field $grant 'EndDateTime')) { 'No active end date returned' } else { 'Time-bound active schedule' })
        PolicyMatch='Not applicable to standing/active schedule'; PolicyId=''
        ActivationMFA=''; CAContextEnabled=''; CAContextId=''; ApprovalRequired=''; JustificationRequired=''
        PermanentEligibleAllowed=''; EligibleMaxDuration=''; ActivationMaxDuration=''; PermanentActiveAllowed=''
        ActivationSafeguard='Not assessed for active role grant'; Condition=(Read-Field $grant 'Condition')
    })
}
$allRegisterPath = Join-Path $output 'All-Privileged-Access-Evidence.csv'
$allEvidence.ToArray() | Export-Csv -LiteralPath $allRegisterPath -NoTypeInformation -Encoding utf8

$review = [System.Collections.Generic.List[object]]::new()
foreach ($g in $standingHighBroad) {
    $grantScope = Read-Field $g 'AssignmentScope'
    $scopeKind = Get-ScopeType $g
    $tier = Get-Tier $g
    $reason = "Direct active $tier role at $scopeKind scope; no assignment end date returned. Validate necessity, PIM for Groups (if applicable) and privilege minimisation."
    [void]$review.Add([pscustomobject][ordered]@{
        FindingId=('SA-'+('{0:D3}' -f ($review.Count+1))); Stream='Standing active RBAC'; Priority=$(if($tier -eq 'Critical' -and $scopeKind -eq 'ManagementGroup'){'High review'}else{'Review'})
        Role=(Read-Field $g 'Role'); Tier=$tier; ScopeKind=$scopeKind; ScopePath=(Get-PathLabels $grantScope); GrantScope=$grantScope
        DescendantSubscriptionsObserved=(Get-ObservedDescendantSubscriptions $grantScope)
        PrincipalId=(Read-Field $g 'PrincipalId'); PrincipalType=(Read-Field $g 'PrincipalType')
        ScheduleId=(Read-Field $g 'ScheduleId'); PolicyId='Not applicable to standing access'
        StartDateTime=(Read-Field $g 'StartDateTime'); EndDateTime=(Read-Field $g 'EndDateTime')
        ActivationMFA='Not applicable'; AuthenticationContext='Not applicable'; Approval='Not applicable'
        Reason=$reason
        NextAction='Confirm holder or group membership, business need, direct scope, RBAC condition and whether PIM for Groups applies. Narrow/revoke if unjustified.'
        ClosureEvidence='Approved privileged-access exception or new scoped assignment with schedule/role-assignment ID and validated effective scope.'
    })
}
foreach ($g in $eligResults) {
    $high = ($g.Tier -in @('Critical','Elevated') -and $g.ScopeKind -in @('ManagementGroup','Subscription'))
    $priority = if ($g.PolicyMatch -ne 'Matched') {'Evidence gap'} elseif ($g.ActivationSafeguard -eq 'No PIM activation MFA or auth. context' -and $high) {'High review'} else {'Review'}
    $reason = if ($g.PolicyMatch -ne 'Matched') {'PIM eligibility exists but policy not unambiguously matched at its exact scope and role.'}
        elseif ($g.ActivationSafeguard -eq 'No PIM activation MFA or auth. context') {'PIM policy requires neither explicit activation MFA nor an authentication context. Wider Conditional Access not assessed.'}
        else {'Validate role scope, eligible holder, expiry policy and applicable activation controls.'}
    [void]$review.Add([pscustomobject][ordered]@{
        FindingId=('PE-'+('{0:D3}' -f ($review.Count+1))); Stream='PIM eligible'
        Priority=$priority; Role=$g.Role; Tier=$g.Tier; ScopeKind=$g.ScopeKind; ScopePath=$g.ScopePath; GrantScope=$g.GrantScope
        DescendantSubscriptionsObserved=$g.ObservedDescendantSubscriptions
        PrincipalId=$g.PrincipalId; PrincipalType=$g.PrincipalType; ScheduleId=$g.ScheduleId; PolicyId=$g.PolicyId
        StartDateTime=$g.StartDateTime; EndDateTime=$g.EndDateTime; ActivationMFA=$g.ActivationMFA; AuthenticationContext=$g.CAContextEnabled; Approval=$g.ApprovalRequired
        Reason=$reason; NextAction='Confirm activation safeguards, exact-scope policy, membership for group principals, eligible duration and least-privilege scope.'
        ClosureEvidence='Target policy configuration, eligible schedule ID and approval/Conditional Access evidence or documented exception.'
    })
}
$reviewPath = Join-Path $output 'Priority-Review-Register.csv'
$review.ToArray() | Export-Csv -LiteralPath $reviewPath -NoTypeInformation -Encoding utf8

# Collect short, readable audit findings plus a complete traceable appendix.
$mainLines = [System.Collections.Generic.List[string]]::new()
$appendixLines = [System.Collections.Generic.List[string]]::new()
function Add-Main { param([string]$Line='') [void]$mainLines.Add($Line) }
function Add-Appendix { param([string]$Line='') [void]$appendixLines.Add($Line) }

Add-Main '# Azure privileged access: standing roles, PIM eligibility and activation controls'
Add-Main ''
Add-Main '**Purpose:** Scope-aware privileged-access review for platform, access-governance and assurance teams. This is a review of saved Azure resource evidence, not a live access certification.'
Add-Main ''
Add-Main ("**Evidence:** $($status.Count) scanned scopes; $($active.Count) active schedule instances; $($eligible.Count) eligibility schedule instances; $policyRows policy configuration rows. Latest source CSV modified (UTC): $($fileStamp.ToString('yyyy-MM-dd HH:mm:ss')).")
Add-Main ''
Add-Main '## Executive findings and what they mean'
Add-Main ''
Add-Main ("**1. PIM activation authentication omission.** $($noStepUp.Count) of $($matchedElig.Count) actual eligible grants with an unambiguous exact-scope policy match do not require explicit activation MFA or an authentication context. $($unmatchedElig.Count) other collected eligibilities have missing, conflicting or unverified policy evidence. Separately, $policyMfaNo of $policyRows collected policy configurations report ActivationMFA=No (the policy inventory includes roles with no eligible holder). This does not establish whether broader Conditional Access is enforced.")
Add-Main ''
Add-Main ("**2. Standing access does not require PIM activation.** $($standing.Count) of $($currentActive.Count) current direct active schedule records are Assigned / Direct and have no end date returned. These are consistent with standing access. Of these, **$($standingHighBroad.Count)** selected Critical/Elevated assignments originate at management group or subscription level. A PIM eight-hour activation limit does not bound these active grants.")
Add-Main ''
Add-Main ("**3. Eligible privileged reach and expiry.** $($currentEligible.Count) distinct current, non-inherited PIM eligible grants were collected, of which $($groupEligible.Count) are to Group/ForeignGroup principals and $($withoutEligibleEnd.Count) have no end date returned. $($eligibleHighBroad.Count) have Critical/Elevated roles originating at management group/subscription level. Of matched grants without an end date, $($noEndPermitted.Count) are governed by policies allowing permanent eligibility and $($noEndPolicyRequires.Count) by policies requiring expiry (investigation needed).")
Add-Main ''
Add-Main ("**4. Coverage qualifier.** Scan status: $(if ($scanComplete) {'no logged scan failures and counts reconcile'} else {'INCOMPLETE OR NOT FULLY RECONCILED'}). Failed scope queries: $($failedScopes.Count). Additional errors logged: $($errors.Count). Saved API rows reconcile with CSVs: $completeCountMatch ($expectedElig eligible, $expectedActive active expected). Resource-level grants, PIM for Groups, directory PIM and Conditional Access are outside this evidence.")
Add-Main ''
Add-Main '### A 60-second explanation for non-specialists'
Add-Main ''
Add-Main '- **Standing Azure RBAC role:** a principal can exercise granted privileges while its active assignment remains effective, without activating Azure resource PIM.'
Add-Main '- **PIM-eligible role:** a principal can request temporary activation. An eight-hour activation limit does not automatically limit how long eligibility persists.'
Add-Main '- **Grant scope:** a management group role can apply throughout child subscriptions. This is inherited *reach*, not a duplicate grant at every child.'
Add-Main '- **PIM configuration:** role-specific activation, eligibility and expiry controls are configured per role and exact Azure scope. Do not assume policy settings inherit from a parent scope.'
Add-Main ''
Add-Main '## Scope hierarchy: direct grants, with inherited reach shown once'
Add-Main ''
Add-Main 'Numbers below count direct grant records *at the named scope*. Child subscriptions can still be affected by permissions inherited from a parent. Management group entries include the number of descendant subscriptions actually observed in this scan.'
Add-Main ''
Add-Main '```text'
function Add-Tree {
    param([string]$NodeId,[int]$Indent,[System.Collections.Generic.HashSet[string]]$Visited)
    $key = Scope-Key $NodeId
    if (-not $nodeIndex.ContainsKey($key) -or -not $Visited.Add($key)) { return }
    $node = $nodeIndex[$key]
    if ((Read-Field $node 'Kind') -eq 'ResourceGroup') { return }
    $dc = @($standingHighBroad | Where-Object { (Scope-Key $_.AssignmentScope) -eq $key }).Count
    $ec = @($eligibleHighBroad | Where-Object { (Scope-Key $_.AssignmentScope) -eq $key }).Count
    $allE = @($currentEligible | Where-Object { (Scope-Key $_.AssignmentScope) -eq $key }).Count
    $allStanding = @($standing | Where-Object { (Scope-Key $_.AssignmentScope) -eq $key }).Count
    $suffix = if ((Read-Field $node 'Kind') -eq 'ManagementGroup') { "; observed child subscriptions=$(Get-ObservedDescendantSubscriptions (Read-Field $node 'ScopeId'))" } else { '' }
    Add-Main ('{0}{1} {2} [standing={3}, eligible={4}; high privilege standing={5}, high privilege eligible={6}{7}]' -f ('  '*$Indent),$(if ((Read-Field $node 'Kind') -eq 'ManagementGroup') {'MG'}else{'SUB'}),(Safe-TreeName (Read-Field $node 'ScopeName')),$allStanding,$allE,$dc,$ec,$suffix)
    # Indent direct high-privilege grants below their originating scope.
    # Do not invent inherited child grants: RBAC reach is shown by the hierarchy itself.
    $nodeStanding = @($standingHighBroad | Where-Object { (Scope-Key $_.AssignmentScope) -eq $key })
    foreach ($grant in @($nodeStanding | Select-Object -First 6)) {
        $shortId = (Read-Field $grant 'PrincipalId')
        if ($shortId.Length -gt 12) { $shortId = $shortId.Substring(0,12) + '...' }
        Add-Main (('{0}  [ACTIVE] {1} ({2}, principal {3})' -f ('  '*$Indent),(Safe-TreeName (Read-Field $grant 'Role')),(Read-Field $grant 'PrincipalType'),$shortId))
    }
    if ($nodeStanding.Count -gt 6) { Add-Main (('{0}  ... +{1} further active grants in appendix' -f ('  '*$Indent),($nodeStanding.Count-6))) }
    $nodeEligible = @($eligResults | Where-Object { (Scope-Key $_.GrantScope) -eq $key -and $_.Tier -in @('Critical','Elevated') })
    foreach ($grant in @($nodeEligible | Select-Object -First 6)) {
        Add-Main (('{0}  [ELIGIBLE] {1} ({2}; MFA={3}, context={4}; activation={5}; ends={6})' -f ('  '*$Indent),(Safe-TreeName $grant.Role),(Safe-TreeName $grant.PrincipalType),$grant.ActivationMFA,$grant.CAContextEnabled,(Text-Or $grant.ActivationMaxDuration 'Unknown'),$(if($grant.EndDateTime){$grant.EndDateTime}else{'not returned'})))
    }
    if ($nodeEligible.Count -gt 6) { Add-Main (('{0}  ... +{1} further eligibilities in appendix' -f ('  '*$Indent),($nodeEligible.Count-6))) }
    if ($children.ContainsKey($key)) {
        foreach ($child in @($children[$key].ToArray() | Where-Object { (Read-Field $_ 'Kind') -in @('ManagementGroup','Subscription') } | Sort-Object ScopeName)) {
            Add-Tree -NodeId (Read-Field $child 'ScopeId') -Indent ($Indent+1) -Visited $Visited
        }
    }
}
$visitedNodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$topNodes = @($scopes | Where-Object { (Read-Field $_ 'Kind') -ne 'ResourceGroup' -and ((-not (Read-Field $_ 'ParentId')) -or (-not $nodeIndex.ContainsKey((Scope-Key (Read-Field $_ 'ParentId'))))) } | Sort-Object ScopeName)
foreach ($root in $topNodes) { Add-Tree -NodeId (Read-Field $root 'ScopeId') -Indent 0 -Visited $visitedNodes }
foreach ($orphan in @($scopes | Where-Object { (Read-Field $_ 'Kind') -ne 'ResourceGroup' -and (-not $visitedNodes.Contains((Scope-Key (Read-Field $_ 'ScopeId')))) })) {
    Add-Tree -NodeId (Read-Field $orphan 'ScopeId') -Indent 0 -Visited $visitedNodes
}
Add-Main '```'
Add-Main ''
Add-Main 'Direct resource-group grants are excluded from the compact tree but remain in `All-Privileged-Access-Evidence.csv`. Scopes absent or inaccessible cannot be inferred as having no grants.'
Add-Main ''
Add-Main '## Standing access: critical and elevated roles at broad scopes'
Add-Main ''
Add-Main '| Scope level | Role | Direct standing grants |'
Add-Main '|---|---|---:|'
$standingGroups = @($standingHighBroad | Group-Object ScopeKind,Role | Sort-Object Count -Descending)
if ($standingGroups.Count -eq 0) { Add-Main '| No matching grants in scanned data | | 0 |' }
foreach ($g in $standingGroups) {
    $first = $g.Group[0]
    Add-Main ('| {0} | {1} | {2} |' -f (Md-Cell (Get-ScopeType $first)),(Md-Cell (Read-Field $first 'Role')),$g.Count)
}
Add-Main ''
Add-Main "Showing up to $MaxSummaryRows direct high-privilege standing assignments. The complete list, including schedule IDs, is in the evidence appendix and CSV register."
Add-Main ''
Add-Main '| Role | Grant scope / observed child subscriptions | Principal type / object ID | Active expiry | Schedule evidence |'
Add-Main '|---|---|---|---|---|'
foreach ($g in @($standingHighBroad | Select-Object -First $MaxSummaryRows)) {
    $scopeId = Read-Field $g 'AssignmentScope'
    Add-Main ('| {0} | {1} ({2}) / {3} | {4}: `{5}` | {6} | `{7}` |' -f (Md-Cell (Read-Field $g 'Role')),(Md-Cell (Get-PathLabels $scopeId)),(Md-Cell (Get-ScopeType $g)),(Get-ObservedDescendantSubscriptions $scopeId),(Md-Cell (Read-Field $g 'PrincipalType')),(Md-Cell (Read-Field $g 'PrincipalId')), 'No end date returned',(Md-Cell (Read-Field $g 'ScheduleId')))
}
Add-Main ''
Add-Main '### All standing assignments: most common roles and grant levels'
Add-Main ''
Add-Main 'This is a volume view, not a risk ranking. High-privilege items are prioritised above.'
Add-Main ''
Add-Main '| Role | Direct grant level | Standing records with no returned expiry |'
Add-Main '|---|---|---:|'
foreach ($roleScopeGroup in @($standing | Group-Object Role,ScopeKind | Sort-Object Count -Descending | Select-Object -First 15)) {
    $example = $roleScopeGroup.Group[0]
    Add-Main ('| {0} | {1} | {2} |' -f (Md-Cell (Read-Field $example 'Role')),(Md-Cell (Get-ScopeType $example)),$roleScopeGroup.Count)
}
Add-Main ''
Add-Main '## Active assignment types and expiry: re-run of the earlier PowerShell grouping'
Add-Main ''
Add-Main '| Assignment type | Membership route | Expiry reported | Records |'
Add-Main '|---|---|---|---:|'
$activeTypes = @($active | ForEach-Object {
    [pscustomobject]@{
        AssignmentType = $_.AssignmentType
        MemberType = $_.MemberType
        Expiry = $(if (Has-NoExpiry $_.EndDateTime) { 'No end date' } else { 'Time-bound' })
    }
})
foreach ($g in @($activeTypes | Group-Object AssignmentType,MemberType,Expiry | Sort-Object Count -Descending)) {
    $e = $g.Group[0]
    Add-Main ('| {0} | {1} | {2} | {3} |' -f (Md-Cell $e.AssignmentType),(Md-Cell $e.MemberType),(Md-Cell $e.Expiry),$g.Count)
}
Add-Main ''
Add-Main ("{0} current activation records appear in the saved data. AssignmentType=Assigned is active access; AssignmentType=Activated is an activated eligibility. MemberType=Group does not mean PrincipalType=Group." -f $activated.Count)
Add-Main ''
Add-Main '### Time-bound PIM activations observed in active schedules'
Add-Main ''
Add-Main 'These are actual active assignment schedule instances marked Activated, not the underlying eligible grants and not an activation history.'
Add-Main ''
Add-Main '| Role | Principal / membership route | Scope | Activated from | Active period | Evidence schedule |'
Add-Main '|---|---|---|---|---|---|'
foreach ($grant in @($activated | Select-Object -First $MaxSummaryRows)) {
    $period = ('{0} to {1}' -f (Text-Or (Read-Field $grant 'StartDateTime')),(Text-Or (Read-Field $grant 'EndDateTime')))
    Add-Main ('| {0} | {1} ({2}) / {3} | {4} | {5} | {6} | `{7}` |' -f (Md-Cell (Read-Field $grant 'Role')),(Md-Cell (Read-Field $grant 'PrincipalId')),(Md-Cell (Read-Field $grant 'PrincipalType')),(Md-Cell (Read-Field $grant 'MemberType')),(Md-Cell (Read-Field $grant 'AssignmentScope')),(Md-Cell (Read-Field $grant 'LinkedRoleEligibilityScheduleId')),(Md-Cell $period),(Md-Cell (Read-Field $grant 'ScheduleId')))
}
if ($activated.Count -eq 0) { Add-Main '| No current Activated schedule instances in collected data | | | | | |' }
Add-Main ''
Add-Main '## PIM eligible assignments and their *configured* activation settings'
Add-Main ''
Add-Main ("Exact-scope policy matches: **$($matchedElig.Count)/$($eligResults.Count)**. Missing or conflicting policy evidence: **$($unmatchedElig.Count)**. Matched assignments with neither PIM activation MFA nor authentication context: **$($noStepUp.Count)**. No end date: **$($withoutEligibleEnd.Count)**. These count eligible assignments, not thousands of unused PIM policy configurations.")
Add-Main ''
Add-Main '| Role (tier) | Exact grant scope | Holder / type | Eligible ends | Permanent eligibility permitted | PIM MFA / context / approval | Activation max | Policy match |'
Add-Main '|---|---|---|---|---|---|---|---|'
foreach ($g in @($eligResults | Sort-Object Tier,ScopeKind,Role,GrantScope | Select-Object -First $MaxSummaryRows)) {
    Add-Main ('| {0} ({1}) | {2} | {3} ({4}) | {5} | {6} | {7} / {8} / {9} | {10} | {11} |' -f (Md-Cell $g.Role),(Md-Cell $g.Tier),(Md-Cell $g.ScopePath),(Md-Cell $g.PrincipalName),(Md-Cell $g.PrincipalType),$(if($g.EndDateTime){Md-Cell $g.EndDateTime}else{'No end date returned'}),(Md-Cell $g.PermanentEligibleAllowed),(Md-Cell $g.ActivationMFA),(Md-Cell $g.CAContextEnabled),(Md-Cell $g.ApprovalRequired),(Md-Cell $g.ActivationMaxDuration),(Md-Cell $g.PolicyMatch))
}
Add-Main ''
Add-Main '### Assignment expiry and configuration are different'
Add-Main ''
Add-Main ("- **$($noEndPermitted.Count)** matched eligibilities have no end date and a policy that permits permanent eligibility. These assignments may remain eligible indefinitely until removed. Their activation window remains separately limited by the policy.")
Add-Main ("- **$($noEndPolicyRequires.Count)** matched eligibilities have no end date but a policy that requires expiry. Review the actual schedule's expiration type and policy timing before classifying this as a violation.")
Add-Main '- A policy value such as `PT8H` is the maximum activation duration, not the eligibility expiry. `P365D` is a maximum for *time-bound* eligibility, not an automatic one-year expiry for a permanent eligible assignment.'
Add-Main ''
Add-Main '## Other collected PIM policy configurations (not necessarily used)'
Add-Main ''
Add-Main '| Policy configuration field | Yes | No | Unknown |'
Add-Main '|---|---:|---:|---:|'
Add-Main "| Explicit PIM activation MFA | $policyMfaYes | $policyMfaNo | $policyMfaUnknown |"
Add-Main "| PIM authentication context | $policyCtxYes | $policyCtxNo | $policyCtxUnknown |"
Add-Main ''
Add-Main 'These are role policy configuration rows, not principals or grants. A high policy count may include many roles with no eligible or active assignment. Absence of a PIM authentication-context rule does not establish that organisation-wide Conditional Access is absent.'
Add-Main ''
Add-Main '## Outstanding evidence and priority actions'
Add-Main ''
Add-Main '1. **Access owners:** Review each Critical/Elevated standing grant at management group and subscription scope. Validate the holder, necessity, condition and intended descendant reach. Narrow/revoke where not justified.'
Add-Main '2. **PIM owners:** Review each matched actual eligibility whose policy requires neither activation MFA nor authentication context. Agree a step-up and approval baseline and independently validate applicable Conditional Access.'
Add-Main '3. **Identity governance:** Resolve group members and PIM for Groups eligibility before claiming that a group role assignment is permanently accessible to any given user.'
Add-Main '4. **Scope owners:** Confirm expiry and activation rules separately, and evaluate whether management group scope is justified for each eligible admin principal.'
Add-Main '5. **Assurance:** Address failed/unscanned scopes, custom role definitions, resource-level grants and role assignment conditions. Record policy and schedule IDs in remediation tickets.'
Add-Main ''
Add-Main '### Evidence required to close a review'
Add-Main ''
Add-Main 'Record the actual schedule ID, principal ID/type, role definition GUID, exact grant scope, observed child subscription reach, business-approved necessity, applicable condition, group membership where relevant, and current policy settings (policy ID, MFA/context, approval, duration). Record a validated new assignment/policy snapshot or formally accepted exception.'
Add-Main ''
Add-Main '### Provenance and limitations'
Add-Main ''
Add-Main ('- Source: completed `pim_eligible_assignments.csv` ({0} rows), `pim_active_schedule_instances.csv` ({1} rows), `observed_scope_hierarchy.csv` ({2} rows) and `scan_status.csv` ({3} rows).' -f $eligible.Count,$active.Count,$scopes.Count,$status.Count)
Add-Main ("- PIM policies: policy_settings.csv ($policyRows rows, $policyRowsMatched rows matched at a scope and role needed by current eligibilities). Source: $policySource")
Add-Main ("- Validation: CSV counts $(if ($completeCountMatch) {'reconcile'}else{'DO NOT RECONCILE'}) with scan status; $($failedScopes.Count) scopes had failed eligibility or active queries; $($errors.Count) recorded error entries.")
Add-Main ('- Optional separately collected RBAC CSV: {0}. Do not add its counts to active schedules because the same grants may appear in both.' -f $(if ($optionalRbac.Count) {"$($optionalRbac.Count) rows"} else {'not supplied'}))
Add-Main '- This is a saved point-in-time observation. File modified times are not necessarily the time Azure returned each assignment. Claims of tenant-wide completeness require tenant-wide coverage and no failed or excluded scopes.'
Add-Main '- Custom roles classified as Unclassified need permission-level analysis. The present dataset does not verify Conditional Access, PIM for Groups, directory-role PIM, membership, business justification or unscanned resource-level assignments.'
Add-Main '- Azure resource PIM and Azure RBAC refer to different control layers. Activation MFA is irrelevant to a standing `Assigned` schedule until the standing access is removed or converted to eligible.'
Add-Main ''
Add-Main '**References:** [Azure RBAC and PIM integration](https://learn.microsoft.com/en-us/azure/role-based-access-control/pim-integration) and [Azure assignment schedule instance fields](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignment-schedule-instances/get?view=rest-authorization-2020-10-01).'

Add-Appendix '# Azure privileged access: complete technical evidence appendix'
Add-Appendix ''
Add-Appendix 'This appendix preserves the evidence identifiers necessary to investigate individual findings. Scope and role IDs are reported at their originating grant scope; inheritance is not duplicated.'
Add-Appendix ''
Add-Appendix '## A. Critical/elevated standing assignments at management group and subscription level'
Add-Appendix ''
$line = 0
foreach ($g in $standingHighBroad) {
    $line++
    Add-Appendix ("### SA-$('{0:D3}' -f $line): $(Md-Cell (Read-Field $g 'Role')) at $(Md-Cell (Read-Field $g 'AssignmentScope'))")
    Add-Appendix ''
    Add-Appendix ("- **Principal:** $(Md-Cell (Read-Field $g 'PrincipalId')) (type $(Md-Cell (Read-Field $g 'PrincipalType'))).")
    Add-Appendix ("- **Classification:** AssignmentType=Assigned; MemberType=Direct; status=$(Md-Cell (Read-Field $g 'Status')); end date=$(Md-Cell (Read-Field $g 'EndDateTime')). This is consistent with a direct standing active grant, subject to verification of its schedule and group path.")
    Add-Appendix ("- **Scope hierarchy:** $(Md-Cell (Get-PathLabels (Read-Field $g 'AssignmentScope'))). Descendant subscriptions observed: $(Get-ObservedDescendantSubscriptions (Read-Field $g 'AssignmentScope')).")
    Add-Appendix ('- **Schedule instance:** `{0}`; role GUID `{1}`; original role assignment ID `{2}`.' -f (Md-Cell (Read-Field $g 'ScheduleId')),(Role-Key (Read-Field $g 'RoleGuid')),(Md-Cell (Read-Field $g 'OriginRoleAssignmentId')))
    Add-Appendix ("- **Condition:** $(Md-Cell (Read-Field $g 'Condition')).")
    Add-Appendix '- **Action:** Confirm the scope and business requirement. If this is a group principal, investigate membership and PIM for Groups separately. Validate current state before changing permissions.'
    Add-Appendix ''
}
if ($standingHighBroad.Count -eq 0) { Add-Appendix 'No Critical/Elevated direct standing grants found at the selected broad scopes in this scan.' }
Add-Appendix ''
Add-Appendix '## B. All current, non-inherited PIM-eligible grants with matched policies'
Add-Appendix ''
foreach ($g in $eligResults) {
    Add-Appendix ("### $(Md-Cell $g.Role) at $(Md-Cell $g.GrantScope)")
    Add-Appendix ''
    Add-Appendix ('- **Holder:** {0}, type {1}, object ID `{2}`; MemberType {3}.' -f (Md-Cell $g.PrincipalName),(Md-Cell $g.PrincipalType),(Md-Cell $g.PrincipalId),(Md-Cell $g.MemberType))
    Add-Appendix ('- **Schedule:** `{0}`; role definition GUID `{1}`; start `{2}`, end `{3}`.' -f (Md-Cell $g.ScheduleId),(Md-Cell $g.RoleGuid),(Md-Cell $g.StartDateTime),(Md-Cell $g.EndDateTime))
    Add-Appendix ("- **Reach:** $(Md-Cell $g.ScopePath); observed descendant subscriptions: $($g.ObservedDescendantSubscriptions).")
    Add-Appendix ('- **Policy match:** {0}; policy ID `{1}`; PIM MFA {2}; context {3}; approval {4}; justification {5}.' -f (Md-Cell $g.PolicyMatch),(Md-Cell $g.PolicyId),(Md-Cell $g.ActivationMFA),(Md-Cell $g.CAContextEnabled),(Md-Cell $g.ApprovalRequired),(Md-Cell $g.JustificationRequired))
    Add-Appendix ('- **Expiry settings:** permanent eligibility allowed {0}; maximum time-bound eligibility `{1}`; maximum activation `{2}`. Actual eligibility expiry is independent of activation duration.' -f (Md-Cell $g.PermanentEligibleAllowed),(Md-Cell $g.EligibleMaxDuration),(Md-Cell $g.ActivationMaxDuration))
    Add-Appendix ("- **Review:** $(Md-Cell $g.ActivationSafeguard). Group membership and wider Conditional Access not proven.")
    Add-Appendix ''
}
Add-Appendix '## C. Scope scan failures and unresolved policy matches'
Add-Appendix ''
Add-Appendix '| Scope | Eligibility scan | Active schedule scan |'
Add-Appendix '|---|---|---|'
foreach ($s in $failedScopes) { Add-Appendix ('| {0} | {1} | {2} |' -f (Md-Cell (Read-Field $s 'ScopeId')),(Md-Cell (Read-Field $s 'Eligible')),(Md-Cell (Read-Field $s 'ActiveSchedule'))) }
if ($failedScopes.Count -eq 0) { Add-Appendix '| None in scan status | | |' }
Add-Appendix ''
foreach ($g in $unmatchedElig) { Add-Appendix ('- **Unresolved policy:** {0} at `{1}`; schedule `{2}`; match state {3}.' -f (Md-Cell $g.Role),(Md-Cell $g.GrantScope),(Md-Cell $g.ScheduleId),(Md-Cell $g.PolicyMatch)) }
Add-Appendix ''
Add-Appendix 'The full data register includes all active roles, not only the broad or privileged examples above.'

$mainPath = Join-Path $output 'Azure-Privileged-Access-Confluence-Review.md'
$appendixPath = Join-Path $output 'Azure-Privileged-Access-Evidence-Appendix.md'
$mainLines.ToArray() | Set-Content -LiteralPath $mainPath -Encoding utf8 -ErrorAction Stop
$appendixLines.ToArray() | Set-Content -LiteralPath $appendixPath -Encoding utf8 -ErrorAction Stop

Write-Host "New Confluence report: $mainPath" -ForegroundColor Green
Write-Host "Evidence appendix:      $appendixPath" -ForegroundColor Green
Write-Host "Priority action CSV:     $reviewPath" -ForegroundColor Green
Write-Host "All assignments CSV:     $allRegisterPath" -ForegroundColor Green
Write-Host ("Collected: {0} eligible, {1} active; direct standing without expiry {2}, broad high-privilege standing {3}, policy matches {4}, no PIM activation MFA/context {5}." -f $eligible.Count,$active.Count,$standing.Count,$standingHighBroad.Count,$matchedElig.Count,$noStepUp.Count) -ForegroundColor Cyan
Write-Host 'Offline only. Source CSVs and previous reports were not changed.' -ForegroundColor Cyan
