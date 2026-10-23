#requires -Version 7.0
<#
.SYNOPSIS
  Link actual Azure-resource PIM eligible assignments to their configured role policies.
.DESCRIPTION
  Reads the EXISTING PIM scope audit and policy_settings.csv. No Azure or Microsoft Graph
  queries, no elevated rights and no changes to existing evidence/reports.

  The report distinguishes a person's/group's actual eligibility end date from the
  policy setting that permits permanent eligibility or requires expiry.

  Each match uses the exact ARM grant scope + role-definition GUID. A policy on a
  parent management group is NEVER substituted for a child's policy.

  Optional friendly principal names come from the previous assignee/expiry register.
  When unavailable, the original principal ID and type are retained.
.EXAMPLE
  .\New-AzurePimConfiguredEligibilityReview.ps1 `
      -ScopeAuditDirectory '.\PIMScopeAudit' `
      -PolicySettingsCsv '.\AzurePimReport\PimAnalysis_20261022_093616\policy_settings.csv'
.NOTES
  PowerShell 7. Offline only. The resulting reports contain privileged access
  details and principal identifiers; restrict Confluence page access appropriately.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $ScopeAuditDirectory,
    [Parameter(Mandatory)][string] $PolicySettingsCsv,
    [string] $OutputDirectory,
    [string] $AssigneeExpiryCsv
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Value {
    param($Record, [string]$Field)
    if ($null -eq $Record) { return '' }
    $property = $Record.PSObject.Properties[$Field]
    if ($null -eq $property -or $null -eq $property.Value) { return '' }
    return [string]$property.Value
}
function Normalise-Scope {
    param([string]$ScopeId)
    if ([string]::IsNullOrWhiteSpace($ScopeId)) { return '' }
    return $ScopeId.Trim().TrimEnd('/').ToLowerInvariant()
}
function Normalise-Role {
    param([string]$RoleId)
    if ([string]::IsNullOrWhiteSpace($RoleId)) { return '' }
    return ($RoleId.Trim().TrimEnd('/') -split '/')[-1].ToLowerInvariant()
}
function Get-JoinKey {
    param([string]$ScopeId, [string]$RoleId)
    return (Normalise-Scope $ScopeId) + '|' + (Normalise-Role $RoleId)
}
function Get-YN {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'Unknown' }
    switch ($Value.Trim().ToLowerInvariant()) {
        { $_ -in @('yes','true','1') } { return 'Yes' }
        { $_ -in @('no','false','0') } { return 'No' }
        default { return 'Unknown' }
    }
}
function Format-MarkdownCell {
    param($Value)
    $v = [string]$Value
    if ([string]::IsNullOrWhiteSpace($v)) { return 'Not recorded' }
    return $v.Replace('|', '\|').Replace("`r",' ').Replace("`n",' ').Replace('`','')
}
function Format-Duration {
    param([string]$IsoValue)
    if ([string]::IsNullOrWhiteSpace($IsoValue)) { return 'Not recorded' }
    try {
        $span = [System.Xml.XmlConvert]::ToTimeSpan($IsoValue)
        if ($span.TotalDays -ge 1) { return ('{0} ({1:N0} days)' -f $IsoValue, $span.TotalDays) }
        return ('{0} ({1:N1} hours)' -f $IsoValue, $span.TotalHours)
    }
    catch { return $IsoValue }
}
function Get-ScopeLabel {
    param([string]$Scope, [string]$Hierarchy)
    if (-not [string]::IsNullOrWhiteSpace($Hierarchy)) { return $Hierarchy }
    return $Scope
}
function Get-PolicyDisposition {
    param($Evidence)
    if ((Get-Value $Evidence 'PolicySource') -ne 'Matched by exact scope and role') {
        return 'Policy settings unverified'
    }
    switch (Get-Value $Evidence 'ConfiguredPermanentEligible') {
        'Yes' { return 'Permanent eligibility permitted' }
        'No'  { return 'Expiry required by policy' }
        default { return 'Eligibility expiration rule unknown' }
    }
}
function Get-ReviewPriority {
    param($Evidence)
    if ((Get-Value $Evidence 'PolicySource') -ne 'Matched by exact scope and role') {
        return 'Unverified: missing or conflicting policy evidence'
    }
    $tier = Get-Value $Evidence 'Tier'
    $scopeKind = Get-Value $Evidence 'ScopeKind'
    $mfa = Get-Value $Evidence 'ActivationMFA'
    $ctx = Get-Value $Evidence 'CAContextEnabled'
    $permanent = Get-Value $Evidence 'ConfiguredPermanentEligible'
    $noDate = [string]::IsNullOrWhiteSpace((Get-Value $Evidence 'AssignmentEnd'))
    if ($noDate -and $permanent -eq 'No') { return 'Investigate: no assignment expiry despite expiry-required policy' }
    if ($tier -in @('Critical','Elevated') -and $scopeKind -in @('ManagementGroup','Subscription') -and
        $mfa -eq 'No' -and $ctx -eq 'No') { return 'Priority: broad privileged eligibility without explicit PIM activation MFA/context' }
    if ($tier -in @('Critical','Elevated') -and $permanent -eq 'Yes' -and $noDate) {
        return 'Review: privileged eligibility without an end date'
    }
    if ($mfa -eq 'Unknown' -or $ctx -eq 'Unknown' -or $permanent -eq 'Unknown') {
        return 'Unverified: missing policy rule'
    }
    return 'Review against agreed access standard'
}

$scanDir = (Resolve-Path -LiteralPath $ScopeAuditDirectory -ErrorAction Stop).Path
$policyFile = (Resolve-Path -LiteralPath $PolicySettingsCsv -ErrorAction Stop).Path
$eligibilityFile = Join-Path $scanDir 'pim_eligible_assignments.csv'
if (-not (Test-Path -LiteralPath $eligibilityFile -PathType Leaf)) {
    throw "Missing saved eligibility file: $eligibilityFile"
}
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $scanDir 'ConfiguredEligibilityReview' }
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop)
$outDir = (Resolve-Path -LiteralPath $OutputDirectory).Path

$assignments = @(Import-Csv -LiteralPath $eligibilityFile -ErrorAction Stop)
if ($assignments.Count -eq 0) { throw 'The eligibility CSV contains no assignments.' }
foreach ($name in @('Status','MemberType','AssignmentScope','RoleGuid','ScheduleId','PrincipalId','EndDateTime','Role')) {
    if ($name -notin $assignments[0].PSObject.Properties.Name) {
        throw "The eligibility file is missing column '$name'. Use the Get-AzurePimScopeEvidence-v3.ps1 CSV."
    }
}

$seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$direct = [System.Collections.Generic.List[object]]::new()
foreach ($a in $assignments) {
    if ((Get-Value $a 'Status') -ne 'Current') { continue }
    if ((Get-Value $a 'MemberType') -eq 'Inherited') { continue }
    $schedule = Get-Value $a 'ScheduleId'
    $id = if ($schedule) { $schedule } else {
        (@((Get-Value $a 'PrincipalId'),(Get-Value $a 'RoleGuid'),(Get-Value $a 'AssignmentScope'),(Get-Value $a 'StartDateTime')) -join '|')
    }
    if ($seen.Add($id)) { [void]$direct.Add($a) }
}
if ($direct.Count -eq 0) { throw 'No current, direct PIM eligibilities were found in the saved CSV.' }

# Build a small set of exact scope + role keys first. Stream policy CSV rows,
# retaining only those needed for current PIM eligibility records.
$wanted = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($a in $direct) {
    $roleGuid = Get-Value $a 'RoleGuid'
    if (-not $roleGuid) { $roleGuid = Get-Value $a 'RoleDefinitionId' }
    [void]$wanted.Add((Get-JoinKey (Get-Value $a 'AssignmentScope') $roleGuid))
}
$policyCandidates = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$policyCsvRowsRead = 0L
$policyCsvMatches = 0L
Write-Host "Reading saved policy settings for $($direct.Count) current direct eligibilities..." -ForegroundColor Cyan
Import-Csv -LiteralPath $policyFile -ErrorAction Stop | ForEach-Object {
    $policyCsvRowsRead++
    $key = Get-JoinKey (Get-Value $_ 'ScopeId') (Get-Value $_ 'RoleGuid')
    if ($wanted.Contains($key)) {
        $policyCsvMatches++
        if (-not $policyCandidates.ContainsKey($key)) {
            $policyCandidates.Add($key, [System.Collections.Generic.List[object]]::new())
        }
        [void]$policyCandidates[$key].Add($_)
    }
}

# Reuse names returned by the prior targeted ARM eligibility read, if present.
# This does not require Graph or another ARM query.
if (-not $AssigneeExpiryCsv) {
    $possible = Join-Path $scanDir 'AssigneeExpiryReview\Azure-PIM-Assignee-Expiry-Register.csv'
    if (Test-Path -LiteralPath $possible -PathType Leaf) { $AssigneeExpiryCsv = $possible }
}
$namesBySchedule = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
if ($AssigneeExpiryCsv) {
    $namePath = (Resolve-Path -LiteralPath $AssigneeExpiryCsv -ErrorAction Stop).Path
    foreach ($item in @(Import-Csv -LiteralPath $namePath -ErrorAction Stop)) {
        $sid = Get-Value $item 'ScheduleId'
        if ($sid -and -not $namesBySchedule.ContainsKey($sid)) { $namesBySchedule.Add($sid,$item) }
    }
}

# Role-specific identical snapshots can be repeated in the source. That is
# not an ambiguity. Distinct policies/rules for one exact scope+role are.
$results = [System.Collections.Generic.List[object]]::new()
foreach ($a in $direct) {
    $scope = Get-Value $a 'AssignmentScope'
    $roleGuid = Get-Value $a 'RoleGuid'
    if (-not $roleGuid) { $roleGuid = Get-Value $a 'RoleDefinitionId' }
    $key = Get-JoinKey $scope $roleGuid
    $policy = $null
    $matchStatus = 'Not collected (no matching role policy at exact scope)'
    $candidateIds = ''
    if ($policyCandidates.ContainsKey($key)) {
        $candidates = @($policyCandidates[$key].ToArray())
        $signatures = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $valid = [System.Collections.Generic.List[object]]::new()
        foreach ($p in $candidates) {
            $signature = @(
                (Get-Value $p 'PolicyId'),(Get-Value $p 'PermanentEligibleAllowed'),
                (Get-Value $p 'EligibleMaxDuration'),(Get-Value $p 'PermanentActiveAllowed'),
                (Get-Value $p 'ActivationMFA'),(Get-Value $p 'CAContextEnabled'),
                (Get-Value $p 'CAContextId'),(Get-Value $p 'ApprovalRequired'),
                (Get-Value $p 'ActivationMaxDuration'),(Get-Value $p 'JustificationRequired'),
                (Get-Value $p 'ScopeMatch'),(Get-Value $p 'RuleCount')
            ) -join '|'
            if ($signatures.Add($signature)) { [void]$valid.Add($p) }
        }
        $candidateIds = (@($valid.ToArray() | ForEach-Object { Get-Value $_ 'PolicyId' }) | Sort-Object -Unique) -join '; '
        if ($valid.Count -ne 1) {
            $matchStatus = 'Ambiguous: multiple different policy records for exact scope+role'
        }
        else {
            $candidate = $valid[0]
            $ruleCount = 0
            $rc = Get-Value $candidate 'RuleCount'
            $ruleParsed = [int]::TryParse($rc, [ref]$ruleCount)
            if ((Get-Value $candidate 'ScopeMatch') -eq 'MISMATCH') {
                $matchStatus = 'Unverified: source policy scope mismatch'
            }
            elseif (-not $ruleParsed -or $ruleCount -le 0) {
                $matchStatus = 'Unverified: policy rules absent'
            }
            else {
                $policy = $candidate
                $matchStatus = 'Matched by exact scope and role'
            }
        }
    }
    $relatedAssignee = $null
    $scheduleId = Get-Value $a 'ScheduleId'
    if ($scheduleId -and $namesBySchedule.ContainsKey($scheduleId)) {
        $relatedAssignee = $namesBySchedule[$scheduleId]
    }
    $principalName = Get-Value $relatedAssignee 'PrincipalName'
    $principalEmail = Get-Value $relatedAssignee 'PrincipalEmail'
    $principalType = Get-Value $a 'PrincipalType'
    if (-not $principalType) { $principalType = Get-Value $relatedAssignee 'PrincipalType' }
    if (-not $principalType) { $principalType = 'Unknown' }
    $reportedExpiry = Get-Value $a 'EndDateTime'
    $permanent = if ($null -ne $policy) { Get-YN (Get-Value $policy 'PermanentEligibleAllowed') } else { 'Unknown' }
    $maxEligible = if ($null -ne $policy) { Get-Value $policy 'EligibleMaxDuration' } else { '' }
    $assessment = 'Policy not verified'
    if ($null -ne $policy) {
        if ($permanent -eq 'Yes') {
            $assessment = if ($reportedExpiry) { 'Permanent eligibility permitted; this grant has an end date' } else { 'Permanent eligibility permitted; no grant end date recorded' }
        }
        elseif ($permanent -eq 'No') {
            $assessment = if ($reportedExpiry) { 'Expiry required; grant has an end date' } else { 'REVIEW: policy requires expiry but grant has no recorded end date' }
        }
        else { $assessment = 'Policy expiration rule unresolved' }
    }
    [void]$results.Add([pscustomobject][ordered]@{
        Role=(Get-Value $a 'Role')
        Tier=(Get-Value $a 'Tier')
        ScopeKind=(Get-Value $a 'ScopeKind')
        ScopeName=(Get-Value $a 'ScopeName')
        ScopePath=(Get-Value $a 'ScopePath')
        AssignmentScope=$scope
        PrincipalType=$principalType
        PrincipalName=$principalName
        PrincipalEmail=$principalEmail
        PrincipalId=(Get-Value $a 'PrincipalId')
        MemberType=(Get-Value $a 'MemberType')
        AssignmentStart=(Get-Value $a 'StartDateTime')
        AssignmentEnd=$reportedExpiry
        EligibilityExpiryAssessment=$assessment
        ConfiguredPermanentEligible=$permanent
        ConfiguredEligibleMaxDuration=$maxEligible
        ConfiguredPermanentActive=$(if($null -ne $policy){Get-YN (Get-Value $policy 'PermanentActiveAllowed')}else{'Unknown'})
        ConfiguredActiveMaxDuration=$(if($null -ne $policy){Get-Value $policy 'ActiveMaxDuration'}else{''})
        ConfiguredActivationMaxDuration=$(if($null -ne $policy){Get-Value $policy 'ActivationMaxDuration'}else{''})
        ActivationMFA=$(if($null -ne $policy){Get-YN (Get-Value $policy 'ActivationMFA')}else{'Unknown'})
        CAContextEnabled=$(if($null -ne $policy){Get-YN (Get-Value $policy 'CAContextEnabled')}else{'Unknown'})
        CAContextId=$(if($null -ne $policy){Get-Value $policy 'CAContextId'}else{''})
        ApprovalRequired=$(if($null -ne $policy){Get-YN (Get-Value $policy 'ApprovalRequired')}else{'Unknown'})
        JustificationRequired=$(if($null -ne $policy){Get-YN (Get-Value $policy 'JustificationRequired')}else{'Unknown'})
        PolicyId=$(if($null -ne $policy){Get-Value $policy 'PolicyId'}else{$candidateIds})
        PolicyLastModified=$(if($null -ne $policy){Get-Value $policy 'LastModified'}else{''})
        PolicySource= $matchStatus
        EligibilityScheduleId=$scheduleId
        RoleDefinitionId=(Get-Value $a 'RoleDefinitionId')
    })
}

$ordered = @($results.ToArray() | Sort-Object `
    @{Expression={switch($_.Tier){'Critical'{0};'Elevated'{1};default{2}}}}, `
    @{Expression={switch($_.ScopeKind){'ManagementGroup'{0};'Subscription'{1};'ResourceGroup'{2};default{3}}}}, `
    Role, AssignmentScope, PrincipalType, PrincipalName, PrincipalId)

$registerPath = Join-Path $outDir 'Azure-PIM-Configured-Eligibility-Register.csv'
$ordered | Export-Csv -LiteralPath $registerPath -NoTypeInformation -Encoding utf8 -ErrorAction Stop

$matched = @($ordered | Where-Object { $_.PolicySource -eq 'Matched by exact scope and role' })
$unmatched = @($ordered | Where-Object { $_.PolicySource -ne 'Matched by exact scope and role' })
$permanentAllowed = @($matched | Where-Object { $_.ConfiguredPermanentEligible -eq 'Yes' })
$expiryRequired = @($matched | Where-Object { $_.ConfiguredPermanentEligible -eq 'No' })
$noDate = @($ordered | Where-Object { -not $_.AssignmentEnd })
$noSafeguard = @($matched | Where-Object { $_.ActivationMFA -eq 'No' -and $_.CAContextEnabled -eq 'No' })
$groupHolders = @($ordered | Where-Object { $_.PrincipalType -in @('Group','ForeignGroup') })
$criticalBroad = @($ordered | Where-Object { $_.Tier -in @('Critical','Elevated') -and $_.ScopeKind -in @('ManagementGroup','Subscription') })
$inconsistentExpiry = @($matched | Where-Object { $_.ConfiguredPermanentEligible -eq 'No' -and -not $_.AssignmentEnd })

$lines = [System.Collections.Generic.List[string]]::new()
function Add-ReportLine { param([string]$Value='') [void]$script:lines.Add($Value) }
Add-ReportLine '# Azure PIM: eligible assignments mapped to configured policies'
Add-ReportLine ''
Add-ReportLine '**Purpose:** Show the precise Azure role and scope of each current, direct PIM eligibility, who holds it, and the policy settings governing eligibility expiry and activation. This report uses saved evidence and does not query Azure.'
Add-ReportLine ''
Add-ReportLine "- **PIM activation safeguard omission:** $($noSafeguard.Count) of $($matched.Count) matched eligible grants have neither explicit PIM activation MFA nor authentication context configured. Independent Conditional Access was not assessed."
Add-ReportLine "- **$($ordered.Count) direct, current eligibility grants** in the collected evidence; **$($matched.Count) matched** to exact scope-and-role policy settings; **$($unmatched.Count) unmatched or ambiguous**."
Add-ReportLine "- **$($permanentAllowed.Count) matched eligibilities are governed by policies permitting permanent eligibility**; **$($expiryRequired.Count) by policies requiring an eligibility expiry**. This is about policy configuration, not the assignment end date."
Add-ReportLine "- **$($noDate.Count) assignments have no end date recorded**; **$($inconsistentExpiry.Count) of these are attached to matched policies requiring expiry** and need specific validation."
Add-ReportLine "- **$($groupHolders.Count) grants are assigned to Group/ForeignGroup principals**. Group member identities and PIM for Groups are not included in these evidence files."
Add-ReportLine ''
Add-ReportLine '## 1. Priority: PIM activation safeguards and broad privileged eligibility'
Add-ReportLine ''
Add-ReportLine 'Each row represents a **direct eligible grant**, not an inherited duplicate. Azure RBAC scope inheritance means activation at management group level can grant privileges throughout its descendants. The PIM policy is matched only at the original grant scope.'
Add-ReportLine ''
Add-ReportLine '| Role | Grant scope | Holder | PIM MFA | Auth. context | Approval | Permanent eligibility allowed | Max eligible duration | Assignment ends |'
Add-ReportLine '|---|---|---|---|---|---|---|---|---|'
if ($criticalBroad.Count -eq 0) { Add-ReportLine '| No broad Critical/Elevated eligibilities in collected records | | | | | | | | |' }
foreach ($r in $criticalBroad) {
    $who = if ($r.PrincipalName) { "$($r.PrincipalName) ($($r.PrincipalType))" } else { "$($r.PrincipalType): $($r.PrincipalId)" }
    $perm = if ($r.ConfiguredPermanentEligible -eq 'Yes') {'Yes'} elseif ($r.ConfiguredPermanentEligible -eq 'No') {'No'} else {'Unverified'}
    $end = if ($r.AssignmentEnd) { $r.AssignmentEnd } else { 'No end date returned' }
    Add-ReportLine ('| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} |' -f `
        (Format-MarkdownCell $r.Role),(Format-MarkdownCell $r.AssignmentScope),
        (Format-MarkdownCell $who),(Format-MarkdownCell $r.ActivationMFA),
        (Format-MarkdownCell $r.CAContextEnabled),(Format-MarkdownCell $r.ApprovalRequired),
        $perm,(Format-MarkdownCell (Format-Duration $r.ConfiguredEligibleMaxDuration)),
        (Format-MarkdownCell $end))
}
Add-ReportLine ''
Add-ReportLine '## 2. Every current, direct eligibility and its policy'
Add-ReportLine ''
Add-ReportLine 'This is the actionable policy-to-eligibility mapping. `Max eligible duration` only limits time-bound assignments when the policy also permits permanent eligibility.'
Add-ReportLine ''
Add-ReportLine '| # | Role | Holder | Exact grant scope | Actual eligibility end | Configured eligible policy | Eligible max duration | Activation MFA / context | Policy match |'
Add-ReportLine '|---|---|---|---|---|---|---|---|---|'
$number = 0
foreach ($r in $ordered) {
    $number++
    $holder = if ($r.PrincipalName) { "$($r.PrincipalName) ($($r.PrincipalType))" } else { "$($r.PrincipalType): $($r.PrincipalId)" }
    $end = if ($r.AssignmentEnd) { $r.AssignmentEnd } else { 'No end date recorded' }
    $policyText = Get-PolicyDisposition $r
    $safeguard = "MFA $($r.ActivationMFA), Context $($r.CAContextEnabled)"
    Add-ReportLine ('| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} |' -f `
        $number,(Format-MarkdownCell $r.Role),(Format-MarkdownCell $holder),
        (Format-MarkdownCell $r.AssignmentScope),(Format-MarkdownCell $end),
        (Format-MarkdownCell $policyText),(Format-MarkdownCell (Format-Duration $r.ConfiguredEligibleMaxDuration)),
        (Format-MarkdownCell $safeguard),(Format-MarkdownCell $r.PolicySource))
}
Add-ReportLine ''
Add-ReportLine '## 3. Evidence for each eligibility'
Add-ReportLine ''
$number=0
foreach ($r in $ordered) {
    $number++
    Add-ReportLine "### $number. $(Format-MarkdownCell $r.Role) at $(Format-MarkdownCell $r.AssignmentScope)"
    Add-ReportLine ''
    Add-ReportLine ('- **Holder:** {0}; type: {1}; principal ID: `{2}`.' -f (Format-MarkdownCell $r.PrincipalName),(Format-MarkdownCell $r.PrincipalType),(Format-MarkdownCell $r.PrincipalId))
    Add-ReportLine ('- **Current eligible assignment:** start `{0}`; end `{1}`.' -f $(if($r.AssignmentStart){$r.AssignmentStart}else{'not recorded'}), $(if($r.AssignmentEnd){$r.AssignmentEnd}else{'not recorded'}))
    Add-ReportLine ('- **Configured eligibility:** {0}; maximum duration for time-bound eligibility: `{1}`.' -f (Get-PolicyDisposition $r), $(if($r.ConfiguredEligibleMaxDuration){$r.ConfiguredEligibleMaxDuration}else{'unknown'}))
    Add-ReportLine ('- **Activation:** explicit MFA {0}; authentication context {1} {2}; approval {3}; justification {4}; maximum activation `{5}`.' -f $r.ActivationMFA,$r.CAContextEnabled, $(if($r.CAContextId){"($($r.CAContextId))"}else{''}), $r.ApprovalRequired, $r.JustificationRequired, $(if($r.ConfiguredActivationMaxDuration){$r.ConfiguredActivationMaxDuration}else{'unknown'}))
    Add-ReportLine ('- **Active assignment policy:** permanent active allowed {0}; maximum time-bound active assignment `{1}`.' -f $r.ConfiguredPermanentActive, $(if($r.ConfiguredActiveMaxDuration){$r.ConfiguredActiveMaxDuration}else{'unknown'}))
    Add-ReportLine ('- **Review:** {0}. **Policy evidence:** {1}.' -f (Get-ReviewPriority $r), (Format-MarkdownCell $r.PolicySource))
    Add-ReportLine ('- **Eligibility schedule instance:** `{0}`.' -f (Format-MarkdownCell $r.EligibilityScheduleId))
    Add-ReportLine ('- **Role definition:** `{0}`.' -f (Format-MarkdownCell $r.RoleDefinitionId))
    Add-ReportLine ('- **Policy ID:** `{0}`; policy last modified: `{1}`.' -f (Format-MarkdownCell $r.PolicyId), $(if($r.PolicyLastModified){$r.PolicyLastModified}else{'not recorded'}))
    Add-ReportLine ''
}
Add-ReportLine '## 4. Interpretation and validation boundaries'
Add-ReportLine ''
Add-ReportLine '- **Policy allows permanent eligibility** means administrators may create eligible grants with no expiry. It does not mean the administrator must use that option. The time-bound maximum duration is not an enforced upper limit for a permanent grant.'
Add-ReportLine '- **Policy requires expiry** means an eligible grant should have a bounded validity period. A blank assignment expiry alongside this setting needs a targeted review of the saved schedule and the policy as of the assignment date. It is not automatically a confirmed enforcement violation.'
Add-ReportLine '- **Activation duration** is separate from the expiry of eligibility. A long-lived eligible assignment does not mean the role remains continuously active.'
Add-ReportLine '- **PIM activation MFA = No** is not evidence that tenant-wide Conditional Access is absent. This report does not determine that wider protection.'
Add-ReportLine '- **Group principal** identifies the group object assigned eligibility. Members and PIM for Groups eligibility require separate Entra evidence.'
Add-ReportLine '- The saved policy CSV may be incomplete or older than the eligibility export. A missing exact match is an evidence gap, not proof there is no PIM policy. Compare `PolicyLastModified` and source capture dates where available.'
Add-ReportLine '- These are Azure-resource PIM eligibilities only, not active RBAC assignments or Microsoft Entra directory role PIM.'
Add-ReportLine ''
Add-ReportLine '## 5. Remediation evidence checklist'
Add-ReportLine ''
Add-ReportLine 'For each high-privilege eligible assignment, record the owner and approved business need, whether the management group/subscription scope is necessary, group members where relevant, the approved expiry standard, and evidence of PIM step-up protection. Close the review only after a targeted current policy read confirms the configuration and the assignment schedule confirms the principal, grant scope and expiry.'
Add-ReportLine ''
Add-ReportLine ('**Sources:** `pim_eligible_assignments.csv` and `policy_settings.csv`; optional principal names from `Azure-PIM-Assignee-Expiry-Register.csv`. Policy rows scanned: {0:N0}. Matching policy rows: {1:N0}. No Azure or Microsoft Graph API calls were made.' -f $policyCsvRowsRead,$policyCsvMatches)
Add-ReportLine ''
Add-ReportLine 'Policy configuration: https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-resource-roles-configure-role-settings'

$markdownPath = Join-Path $outDir 'Azure-PIM-Configured-Eligibility-Review.md'
$lines.ToArray() | Set-Content -LiteralPath $markdownPath -Encoding utf8 -ErrorAction Stop
Write-Host "Confluence Markdown: $markdownPath" -ForegroundColor Green
Write-Host "Evidence register: $registerPath" -ForegroundColor Green
Write-Host "Current direct eligibilities: $($ordered.Count); exact policy matches: $($matched.Count); unmatched: $($unmatched.Count); group principals: $($groupHolders.Count); grants without end dates: $($noDate.Count)." -ForegroundColor Cyan
Write-Host 'This was an offline join. No Azure or Graph permissions were requested, and no existing evidence files were modified.' -ForegroundColor Cyan
