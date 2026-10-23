#requires -Version 7.0
<#
.SYNOPSIS
    Generate an additional Confluence Markdown review of Azure resource PIM eligibility,
    privilege scope and activation MFA. Uses existing CSV evidence only.
.DESCRIPTION
    Does NOT invoke Azure, Microsoft Graph or any online service.
    Does NOT alter the existing CSV files or the two earlier Markdown reports.

    Shows direct eligible grants at their originating Azure scope in a readable
    management-group > subscription > resource-group tree. Inherited copies and
    duplicate schedule IDs are excluded from the main tree. Independent direct
    grants at both parent and child are retained because they are not duplicates.

    Joins PIM policies on exact (scope ID + role GUID). Policies at parent scopes
    are not treated as inherited configuration at child scopes.
.EXAMPLE
    .\New-AzurePimHierarchyReview.ps1 `
      -ScopeAuditDirectory '.\PIMScopeAudit' `
      -PolicySettingsCsv '.\AzurePimReport\PimAnalysis_20261022_093616\policy_settings.csv'
.NOTES
    Safe for PowerShell 7. No Azure modules required.
    Output contains principal identifiers and access details: restrict Confluence access.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $ScopeAuditDirectory,
    [Parameter(Mandatory)][string] $PolicySettingsCsv,
    [string] $OutputDirectory,
    [ValidateRange(1, 200)][int] $TopFindings = 40
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-RequiredCsv {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file missing: $Path"
    }
    return @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
}
function Get-Field {
    param($Record, [string] $Field)
    if ($null -eq $Record) { return '' }
    $property = $Record.PSObject.Properties[$Field]
    if ($null -eq $property -or $null -eq $property.Value) { return '' }
    return [string]$property.Value
}
function Normalise-ScopeId {
    param([string] $ScopeId)
    if ([string]::IsNullOrWhiteSpace($ScopeId)) { return '' }
    return $ScopeId.Trim().TrimEnd('/').ToLowerInvariant()
}
function Normalise-RoleGuid {
    param([string] $RoleGuid)
    if (-not $RoleGuid) { return '' }
    return ($RoleGuid.Trim() -split '/')[-1].ToLowerInvariant()
}
function Get-MatchKey {
    param([string] $ScopeId, [string] $RoleGuid)
    return (Normalise-ScopeId $ScopeId) + '|' + (Normalise-RoleGuid $RoleGuid)
}
function Get-Flag {
    param([string] $Value)
    switch ($Value.Trim().ToLowerInvariant()) {
        {$_ -in @('yes','true','1')} { return 'Yes' }
        {$_ -in @('no','false','0')} { return 'No' }
        default { return 'Unknown' }
    }
}
function Escape-Md {
    param($Value)
    $valueText = [string]$Value
    if ([string]::IsNullOrWhiteSpace($valueText)) { return 'Not recorded' }
    $valueText = $valueText.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    $valueText = $valueText.Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ')
    return $valueText.Replace('`', '')
}
function Get-Tier {
    param($Evidence)
    $roleGuid = Normalise-RoleGuid (Get-Field $Evidence 'RoleGuid')
    if ($roleGuid -in @('8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
                        '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9',
                        'f58310d9-a9f6-439a-9e8d-f62e7b41a168')) { return 'Critical' }
    if ($roleGuid -eq 'b24988ac-6180-42a0-ab88-20f7382dd24c') { return 'Elevated' }
    $supplied = Get-Field $Evidence 'Tier'
    if ($supplied -in @('Critical','Elevated','Lower','Unclassified')) { return $supplied }
    return 'Unclassified'
}
function Get-ScopeType {
    param($Evidence)
    $kind = Get-Field $Evidence 'ScopeKind'
    if ($kind) { return $kind }
    $scopeId = Normalise-ScopeId (Get-Field $Evidence 'AssignmentScope')
    if ($scopeId -match '^/providers/microsoft.management/managementgroups/[^/]+$') { return 'ManagementGroup' }
    if ($scopeId -match '^/subscriptions/[^/]+$') { return 'Subscription' }
    if ($scopeId -match '^/subscriptions/[^/]+/resourcegroups/[^/]+$') { return 'ResourceGroup' }
    return 'ResourceOrOther'
}
function Get-Order {
    param($Evidence)
    $tier = Get-Tier $Evidence
    $kind = Get-ScopeType $Evidence
    $tierRank = switch ($tier) { 'Critical' {0}; 'Elevated' {1}; 'Unclassified' {2}; default {3} }
    $kindRank = switch ($kind) { 'ManagementGroup' {0}; 'Subscription' {1}; 'ResourceGroup' {2}; default {3} }
    return ($tierRank * 10 + $kindRank)
}
function Add-Line {
    param([string] $Line = '')
    [void] $script:ReportLines.Add($Line)
}

$scanRoot = (Resolve-Path -LiteralPath $ScopeAuditDirectory -ErrorAction Stop).Path
$policyPath = (Resolve-Path -LiteralPath $PolicySettingsCsv -ErrorAction Stop).Path
if (-not $OutputDirectory) { $OutputDirectory = $scanRoot }
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop)
$outRoot = (Resolve-Path -LiteralPath $OutputDirectory).Path

$nodesCsv = @(Read-RequiredCsv (Join-Path $scanRoot 'observed_scope_hierarchy.csv'))
$statuses = @(Read-RequiredCsv (Join-Path $scanRoot 'scan_status.csv'))
$eligibleCsv = @(Read-RequiredCsv (Join-Path $scanRoot 'pim_eligible_assignments.csv'))

foreach ($col in @('ScopeId','ScopeName','Kind','ParentId')) {
    if ($nodesCsv.Count -gt 0 -and -not $nodesCsv[0].PSObject.Properties[$col]) { throw "Hierarchy CSV lacks column '$col'." }
}
foreach ($col in @('AssignmentScope','RoleGuid','PrincipalId','ScheduleId','Status','Tier','Role')) {
    if ($eligibleCsv.Count -gt 0 -and -not $eligibleCsv[0].PSObject.Properties[$col]) { throw "Eligibility CSV lacks column '$col'." }
}
if ($statuses.Count -eq 0 -or $nodesCsv.Count -eq 0) { throw 'Scan hierarchy or status is empty. Do not treat an incomplete scan as a clean result.' }

# Only the grant's originating scope is shown. The original collector already
# removes API rows returned via inheritance (properties.scope != query scope).
$nodes = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$children = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($row in $nodesCsv) {
    $key = Normalise-ScopeId (Get-Field $row 'ScopeId')
    if (-not $key) { continue }
    if ($nodes.ContainsKey($key)) { continue }
    $record = [pscustomobject]@{
        Id = $key
        RawId = Get-Field $row 'ScopeId'
        Name = Get-Field $row 'ScopeName'
        Kind = Get-Field $row 'Kind'
        Parent = Normalise-ScopeId (Get-Field $row 'ParentId')
    }
    $nodes.Add($key, $record)
}
foreach ($node in $nodes.Values) {
    if (-not $children.ContainsKey($node.Parent)) {
        $children.Add($node.Parent, [System.Collections.Generic.List[object]]::new())
    }
    [void]$children[$node.Parent].Add($node)
}

function Get-ChildNodes {
    param([string] $Parent)
    if (-not $children.ContainsKey($Parent)) { return @() }
    $nodeValues = @($children[$Parent] | Sort-Object `
        @{Expression = { switch ($_.Kind) { 'ManagementGroup' {0}; 'Subscription' {1}; 'ResourceGroup' {2}; default {3} } }}, Name)
    return $nodeValues
}
function Get-ObservedReach {
    param([string] $GrantScope)
    $key = Normalise-ScopeId $GrantScope
    if (-not $nodes.ContainsKey($key)) { return [pscustomobject]@{Subscriptions=0;ResourceGroups=0;Known=$false} }
    $subCount = 0
    $rgCount = 0
    foreach ($candidate in $nodes.Values) {
        if ($candidate.Id -eq $key) { continue }
        $cursor = [string]$candidate.Parent
        $guard = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        while ($cursor -and $guard.Add($cursor) -and $nodes.ContainsKey($cursor)) {
            if ($cursor -eq $key) {
                if ($candidate.Kind -eq 'Subscription') { $subCount++ }
                elseif ($candidate.Kind -eq 'ResourceGroup') { $rgCount++ }
                break
            }
            $cursor = [string]$nodes[$cursor].Parent
        }
    }
    if ($nodes[$key].Kind -eq 'Subscription') { $subCount = 1 }
    return [pscustomobject]@{ Subscriptions=$subCount; ResourceGroups=$rgCount; Known=$true }
}
function Is-Ancestor {
    param([string] $PossibleAncestor, [string] $ScopeId)
    $ancestor = Normalise-ScopeId $PossibleAncestor
    $cursor = Normalise-ScopeId $ScopeId
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    while ($cursor -and $seen.Add($cursor) -and $nodes.ContainsKey($cursor)) {
        $cursor = [string]$nodes[$cursor].Parent
        if ($cursor -eq $ancestor) { return $true }
    }
    return $false
}

$seenScheduleIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$direct = [System.Collections.Generic.List[object]]::new()
$excludedInherited = [System.Collections.Generic.List[object]]::new()
$duplicateCount = 0
foreach ($entry in $eligibleCsv) {
    $member = Get-Field $entry 'MemberType'
    if ($member -eq 'Inherited') { [void]$excludedInherited.Add($entry); continue }
    $evidenceId = Get-Field $entry 'ScheduleId'
    if (-not $evidenceId) {
        $evidenceId = @((Get-Field $entry 'PrincipalId'),(Get-Field $entry 'RoleGuid'),(Get-Field $entry 'AssignmentScope'),(Get-Field $entry 'StartDateTime'),(Get-Field $entry 'EndDateTime')) -join '|'
    }
    if (-not $seenScheduleIds.Add($evidenceId)) { $duplicateCount++; continue }
    [void]$direct.Add($entry)
}
$atScan = @($direct | Where-Object { (Get-Field $_ 'Status') -eq 'Current' })
$excludedOtherState = $direct.Count - $atScan.Count
$mgCount = @($nodes.Values | Where-Object Kind -eq 'ManagementGroup').Count
$subCount = @($nodes.Values | Where-Object Kind -eq 'Subscription').Count
$rgCount = @($nodes.Values | Where-Object Kind -eq 'ResourceGroup').Count
$failedScopes = @($statuses | Where-Object { (Get-Field $_ 'Eligible') -ne 'OK' -or (Get-Field $_ 'ActiveSchedule') -ne 'OK' })
$failedEligibility = @($statuses | Where-Object { (Get-Field $_ 'Eligible') -ne 'OK' })

# Important: compare scan_status counts, not just the existence of a CSV file.
$expectedEligible = 0L
foreach ($scanEntry in $statuses) {
    $countText = Get-Field $scanEntry 'DirectEligible'
    $n = 0L
    if ([long]::TryParse($countText, [ref]$n)) { $expectedEligible += $n }
}
if ($expectedEligible -ne $eligibleCsv.Count) {
    throw "Eligibility evidence inconsistent: scan_status reports $expectedEligible rows; pim_eligible_assignments.csv contains $($eligibleCsv.Count). Report not generated."
}

# Stream the large policy CSV once. Store only policies that match eligible
# assignments by exact role GUID and original assignment scope.
$targets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $atScan) {
    [void]$targets.Add((Get-MatchKey (Get-Field $entry 'AssignmentScope') (Get-Field $entry 'RoleGuid')))
}
$policyByKey = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$policyStats = [ordered]@{ Total=0L; NoMfa=0L; YesMfa=0L; UnknownMfa=0L; NoContext=0L; YesContext=0L; UnknownContext=0L; Neither=0L }
Import-Csv -LiteralPath $policyPath -ErrorAction Stop | ForEach-Object {
    $pimPolicy = $_
    $policyStats.Total++
    $mfaValue = Get-Flag (Get-Field $pimPolicy 'ActivationMFA')
    $caValue = Get-Flag (Get-Field $pimPolicy 'CAContextEnabled')
    if ($mfaValue -eq 'Yes') { $policyStats.YesMfa++ }
    elseif ($mfaValue -eq 'No') { $policyStats.NoMfa++ }
    else { $policyStats.UnknownMfa++ }
    if ($caValue -eq 'Yes') { $policyStats.YesContext++ }
    elseif ($caValue -eq 'No') { $policyStats.NoContext++ }
    else { $policyStats.UnknownContext++ }
    if ($mfaValue -eq 'No' -and $caValue -eq 'No') { $policyStats.Neither++ }
    $matchKey = Get-MatchKey (Get-Field $pimPolicy 'ScopeId') (Get-Field $pimPolicy 'RoleGuid')
    if ($targets.Contains($matchKey)) {
    $candidate = [pscustomobject]@{
        Mfa=$mfaValue; Context=$caValue
        ContextId=Get-Field $pimPolicy 'CAContextId'
        Approval=Get-Flag (Get-Field $pimPolicy 'ApprovalRequired')
        Justification=Get-Flag (Get-Field $pimPolicy 'JustificationRequired')
        ActivationMax=Get-Field $pimPolicy 'ActivationMaxDuration'
        PolicyId=Get-Field $pimPolicy 'PolicyId'
        ScopeMatch=Get-Field $pimPolicy 'ScopeMatch'
        RuleCount=Get-Field $pimPolicy 'RuleCount'
        Conflict=$false
    }
    if (-not $policyByKey.ContainsKey($matchKey)) {
        $policyByKey.Add($matchKey,$candidate)
    } else {
        $old = $policyByKey[$matchKey]
        if ($old.Mfa -ne $candidate.Mfa -or $old.Context -ne $candidate.Context -or
            $old.ScopeMatch -ne $candidate.ScopeMatch -or $old.RuleCount -ne $candidate.RuleCount -or
            $old.Approval -ne $candidate.Approval -or $old.PolicyId -ne $candidate.PolicyId -or
            $old.ActivationMax -ne $candidate.ActivationMax) { $old.Conflict = $true }
    }
    }
}
if ($policyStats.Total -eq 0) { throw "Policy CSV is empty: $policyPath" }

$reviewRecords = [System.Collections.Generic.List[object]]::new()
$matchedCount=0; $noBothCount=0; $protectedCount=0; $unverifiedCount=0
foreach ($entry in $atScan) {
    $key = Get-MatchKey (Get-Field $entry 'AssignmentScope') (Get-Field $entry 'RoleGuid')
    $policy = $null
    if ($policyByKey.ContainsKey($key)) { $policy = $policyByKey[$key] }
    $matching = ($null -ne $policy)
    if ($matching) { $matchedCount++ }
    $mfaText = if ($matching) {$policy.Mfa} else {'Not joined'}
    $caText = if ($matching) {$policy.Context} else {'Not joined'}
    $ruleState = 'Unverified'
    if ($matching -and -not $policy.Conflict -and $policy.ScopeMatch -ne 'MISMATCH' -and $policy.RuleCount -ne '0') {
        if ($mfaText -eq 'No' -and $caText -eq 'No') { $ruleState='No explicit activation MFA/context'; $noBothCount++ }
        elseif ($mfaText -eq 'Yes' -or $caText -eq 'Yes') { $ruleState='Explicit activation safeguard configured'; $protectedCount++ }
    }
    if ($ruleState -eq 'Unverified') { $unverifiedCount++ }
    $reach = Get-ObservedReach (Get-Field $entry 'AssignmentScope')
    [void]$reviewRecords.Add([pscustomobject]@{
        Entry=$entry; ScopeId=Normalise-ScopeId (Get-Field $entry 'AssignmentScope')
        Tier=Get-Tier $entry; Kind=Get-ScopeType $entry
        Rank=Get-Order $entry; Reach=$reach; Policy=$policy; RuleState=$ruleState
        Mfa=$mfaText; Context=$caText; ContextId=$(if($matching){$policy.ContextId}else{''})
        Approval=$(if($matching){$policy.Approval}else{'Not joined'})
        Justification=$(if($matching){$policy.Justification}else{'Not joined'})
        ActivationMax=$(if($matching){$policy.ActivationMax}else{'Not joined'})
        PolicyId=$(if($matching){$policy.PolicyId}else{''})
    })
}
$sortedRecords = @($reviewRecords.ToArray() | Sort-Object Rank, @{Expression={$_.Entry.Role}}, ScopeId)
$highLevel = @($sortedRecords | Where-Object { $_.Tier -in @('Critical','Elevated') -and $_.Kind -in @('ManagementGroup','Subscription') })
$criticalHigh = @($highLevel | Where-Object Tier -eq 'Critical')
$unclassified = @($sortedRecords | Where-Object Tier -eq 'Unclassified')

# Detect genuinely separate direct grants to one principal/role at both an
# ancestor and descendant. These are retained and not called inherited copies.
$overlapNotes = [System.Collections.Generic.List[object]]::new()
foreach ($childGrant in $sortedRecords) {
    foreach ($parentGrant in $sortedRecords) {
        if ($childGrant -eq $parentGrant) { continue }
        if ((Get-Field $childGrant.Entry 'PrincipalId') -ne (Get-Field $parentGrant.Entry 'PrincipalId')) { continue }
        if ((Normalise-RoleGuid (Get-Field $childGrant.Entry 'RoleGuid')) -ne (Normalise-RoleGuid (Get-Field $parentGrant.Entry 'RoleGuid'))) { continue }
        if (Is-Ancestor $parentGrant.ScopeId $childGrant.ScopeId) {
            [void]$overlapNotes.Add([pscustomobject]@{Parent=$parentGrant;Child=$childGrant})
        }
    }
}
$byScope = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($record in $sortedRecords) {
    if (-not $byScope.ContainsKey($record.ScopeId)) { $byScope.Add($record.ScopeId, [System.Collections.Generic.List[object]]::new()) }
    [void]$byScope[$record.ScopeId].Add($record)
}
function Get-DirectAtNode {
    param([string]$ScopeId)
    if ($byScope.ContainsKey($ScopeId)) { return @($byScope[$ScopeId].ToArray()) }
    return @()
}
function Get-GrantLabel {
    param([object[]]$Grants)
    if ($Grants.Count -eq 0) { return '' }
    $bits = [System.Collections.Generic.List[string]]::new()
    foreach ($roleGroup in @($Grants | Group-Object { Get-Field $_.Entry 'Role' } | Sort-Object Name)) {
        $roleName = [string]$roleGroup.Name
        $label = if ($roleName -eq 'Owner') { '! Owner' } else { $roleName }
        [void]$bits.Add(('{0} x{1}' -f $label,$roleGroup.Count))
    }
    $missingStepUp = @($Grants | Where-Object RuleState -eq 'No explicit activation MFA/context').Count
    if ($missingStepUp -gt 0) { [void]$bits.Add("NO PIM ACTIVATION MFA/CONTEXT x$missingStepUp") }
    return ('  [DIRECT PIM eligibility: {0}]' -f ($bits -join '; '))
}

$script:ReportLines = [System.Collections.Generic.List[string]]::new()
$statTimestamp = (Get-Item -LiteralPath (Join-Path $scanRoot 'scan_status.csv')).LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm')
Add-Line '# Azure resource PIM: activation MFA and scope of eligible privileges'
Add-Line ''
Add-Line "**Evidence:** read-only Azure export saved at approximately $statTimestamp UTC. **Status:** preliminary review requiring control-owner validation."
Add-Line ''
Add-Line '**Scope of this report:** Eligible PIM assignments and their activation policies only. The 758 active schedule records and any standing RBAC Owner grants belong to the separate existing review. They are not added to eligibility counts.'
Add-Line ''
Add-Line '## 1. Priority finding: PIM activation does not explicitly require MFA across most recorded policies'
Add-Line ''
Add-Line ('**{0:N0} of {1:N0} policy records** have `ActivationMFA = No` and `CAContextEnabled = No`.' -f $policyStats.Neither,$policyStats.Total)
Add-Line ('Across the entire policy inventory, explicit PIM MFA is `No` for **{0:N0}**, `Yes` for **{1:N0}** and unknown for **{2:N0}** records.' -f $policyStats.NoMfa,$policyStats.YesMfa,$policyStats.UnknownMfa)
Add-Line ''
Add-Line ('**Most important, for actual eligible grants:** {0} of {1} eligibilities valid at the scan had exact scope-and-role policy matches; **{2} matched grants** have neither explicit activation MFA nor authentication context enabled. **{3}** have one of those safeguards configured; **{4}** are unresolved.' -f $matchedCount,$atScan.Count,$noBothCount,$protectedCount,$unverifiedCount)
Add-Line ''
Add-Line '**Why this matters:** PIM can give a user elevated Azure permissions when they activate an eligible role. The recorded configuration largely does not demand a PIM-specific MFA or Conditional Access authentication-context step before activation. A normal sign-in Conditional Access policy may still require MFA; those policies were not collected. Do not describe this as proof of MFA bypass, or count unused PIM policies as affected users.'
Add-Line ''
Add-Line '**Proposed action:** Have the PIM and Conditional Access owners confirm the intended activation standard. Prioritise Owner, User Access Administrator and Role Based Access Control Administrator, starting at management group and subscription scope. Require appropriate step-up authentication or an evidenced and approved alternative; verify any exceptions.'
Add-Line ''
Add-Line '## 2. Where the eligible privileges originate'
Add-Line ''
Add-Line ('**{0}** valid-at-scan *direct* eligible schedule instances across **{1} management groups, {2} subscriptions and {3} resource groups** in the observed hierarchy.' -f $atScan.Count,$mgCount,$subCount,$rgCount)
Add-Line ('**{0} critical-role eligibilities** and **{1} additional elevated-role eligibilities** are directly granted at management group or subscription scope. These are prioritised for scope review, not automatically deemed unauthorised.' -f $criticalHigh.Count,($highLevel.Count-$criticalHigh.Count))
Add-Line ''
Add-Line 'A management group grant can cover all its descendant subscriptions **when activated at that scope**. It does not mean those privileges are permanently active. An eligible user may also choose a reduced activation scope. The counts below show *observed potential reach*, not actual activation history.'
Add-Line ''
Add-Line '```text'
function Write-ScopeTree {
    param([string] $NodeId, [string] $Prefix, [bool] $IsLast, [bool] $IsRoot)
    if (-not $nodes.ContainsKey($NodeId)) { return }
    $node = $nodes[$NodeId]
    $joint = if ($IsRoot) { '' } elseif ($IsLast) { '└── ' } else { '├── ' }
    $indentNext = if ($IsRoot) { $Prefix } elseif ($IsLast) { $Prefix + '    ' } else { $Prefix + '│   ' }
    $nodePrefix = switch ($node.Kind) { 'ManagementGroup' {'MG'}; 'Subscription' {'SUB'}; 'ResourceGroup' {'RG'}; default {'SCOPE'} }
    $grants = @(Get-DirectAtNode $node.Id)
    $reach = Get-ObservedReach $node.Id
    $reachText = if ($node.Kind -eq 'ManagementGroup') { ('  [{0} descendant subscriptions observed]' -f $reach.Subscriptions) } else { '' }
    $name = if ($node.Name) {$node.Name} else {$node.RawId}
    Add-Line ($Prefix + $joint + $nodePrefix + ': ' + $name + (Get-GrantLabel $grants) + $reachText)
    $nextNodes = @(Get-ChildNodes $node.Id | Where-Object { $_.Kind -in @('ManagementGroup','Subscription') -or $byScope.ContainsKey($_.Id) })
    $hiddenRgCount = @((Get-ChildNodes $node.Id) | Where-Object { $_.Kind -eq 'ResourceGroup' -and -not $byScope.ContainsKey($_.Id) }).Count
    for ($j=0; $j -lt $nextNodes.Count; $j++) {
        # Keep indentation clear even where a summary line follows the visible children.
        $lastChild = ($j -eq $nextNodes.Count-1 -and $hiddenRgCount -eq 0)
        Write-ScopeTree -NodeId $nextNodes[$j].Id -Prefix $indentNext -IsLast $lastChild -IsRoot $false
    }
    if ($hiddenRgCount -gt 0) {
        Add-Line ($indentNext + '└── ' + "... $hiddenRgCount resource groups without a direct eligible grant omitted")
    }
}
$treeRoots = @($nodes.Values | Where-Object { -not $_.Parent -or -not $nodes.ContainsKey($_.Parent) } | Sort-Object Name)
foreach ($root in $treeRoots) { Write-ScopeTree -NodeId $root.Id -Prefix '' -IsLast $true -IsRoot $true }
Add-Line '```'
Add-Line ''
Add-Line '**Tree legend:** `MG` management group, `SUB` subscription, `RG` resource group. `DIRECT PIM eligibility` is assigned *at that exact node*. Roles that would be effective at a child only because of a parent activation are not repeated at the child. Independent direct parent and child eligibilities are not concealed.'
Add-Line ''
Add-Line '### Direct eligible grants by role sensitivity and assignment level'
Add-Line ''
Add-Line '| Role sensitivity | Management group | Subscription | Resource group | Other | Total |'
Add-Line '|---|---:|---:|---:|---:|---:|'
foreach ($tierName in @('Critical','Elevated','Unclassified','Lower')) {
    $scopeRows = @($sortedRecords | Where-Object Tier -eq $tierName)
    $mg = @($scopeRows | Where-Object Kind -eq 'ManagementGroup').Count
    $sub = @($scopeRows | Where-Object Kind -eq 'Subscription').Count
    $rg = @($scopeRows | Where-Object Kind -eq 'ResourceGroup').Count
    $other = $scopeRows.Count - $mg - $sub - $rg
    Add-Line "| $tierName | $mg | $sub | $rg | $other | $($scopeRows.Count) |"
}
Add-Line ''
Add-Line '**Sensitivity:** Critical = Owner, User Access Administrator or RBAC Administrator. Elevated includes Contributor and other classified administrative roles. Custom or unresolved roles are not assumed safe; review their actual `Actions` and `DataActions`.'
Add-Line ''
Add-Line '## 3. High-privilege eligibilities granted at broad scopes'
Add-Line ''
if ($highLevel.Count -eq 0) {
    Add-Line 'No Critical/Elevated eligibility at management group or subscription scope was returned in the completed scan. This does not establish absence beyond the scanned hierarchy or at resource level.'
} else {
    Add-Line '| Ref | Role | Grant level and exact scope | Principal ID | Observed subscriptions covered | PIM MFA / auth context | Approval | Expiry |'
    Add-Line '|---|---|---|---|---:|---|---|---|'
    $show = @($highLevel | Select-Object -First $TopFindings)
    $k=0
    foreach ($record in $show) {
        $k++
        $raw = $record.Entry
        $reference = ('H{0:D2}' -f $k)
        $scopeLabel = ('{0}: {1}' -f $record.Kind,(Get-Field $raw 'AssignmentScope'))
        $expiration = Get-Field $raw 'EndDateTime'
        if (-not $expiration) { $expiration='No expiry recorded (review)' }
        Add-Line ('| {0} | {1} ({2}) | {3} | `{4}` | {5} | {6} / {7} | {8} | {9} |' -f $reference,(Escape-Md (Get-Field $raw 'Role')),$record.Tier,(Escape-Md $scopeLabel),(Get-Field $raw 'PrincipalId'),$record.Reach.Subscriptions,$record.Mfa,$record.Context,$record.Approval,(Escape-Md $expiration))
    }
    if ($highLevel.Count -gt $TopFindings) { Add-Line ""; Add-Line "Displaying $TopFindings of $($highLevel.Count) broad-scope review candidates. The evidence register below retains all." }
}
Add-Line ''
Add-Line '### Required review for each high-scope grant'
Add-Line ''
Add-Line '1. **Purpose and scope:** Obtain the approved requirement for this role at this scope. If possible, use a smaller scope or a less powerful role. A central platform remit may justify broad access, but the justification must be recorded.'
Add-Line '2. **Activation protection:** Validate the matching PIM policy. A `No / No` result means no *explicit PIM activation* MFA or authentication context, not that tenant-wide sign-in MFA is disabled.'
Add-Line '3. **Principal and expiry:** Verify the principal, any group membership, time limit and whether it still needs eligibility. Existing schedule data does not expand group members.'
Add-Line '4. **Evidence of closure:** Record the schedule ID, direct grant scope, role definition, approved scope, PIM policy ID, control-owner decision and a fresh read-only re-query after any change.'
Add-Line ''
Add-Line '## 4. Other observations and limits'
Add-Line ''
Add-Line ('- **{0} total eligible rows** collected: **{1} valid at scan**, **{2} other lifecycle states**, **{3} explicitly inherited rows removed**, **{4} duplicate schedule IDs removed**. The original CSV remains unchanged.' -f $eligibleCsv.Count,$atScan.Count,$excludedOtherState,$excludedInherited.Count,$duplicateCount)
Add-Line ('- **{0} scopes** had a failed eligibility or active-schedule query; **{1}** had an eligibility-query failure. The report does not treat those scopes as empty.' -f $failedScopes.Count,$failedEligibility.Count)
Add-Line ('- **{0} direct parent-and-child grant overlaps** involving the same principal and role were observed. These are independent grant records and have not been silently deleted.' -f $overlapNotes.Count)
Add-Line '- Parent role activation may be narrowed to a child scope by the eligible user. Actual activation scope, privileged-role usage, Conditional Access policy contents and PIM for Groups are not established by these files.'
Add-Line '- The policy inventory includes configurations for roles that may not have eligible assignments. The eligibility-specific counts join policy settings only at the exact role and scope.'
Add-Line '- PIM policy rules do not inherit across Azure resource scopes. RBAC grants do. Do not apply a management group PIM policy automatically to a child role eligibility.'
Add-Line '- The report is based on the saved scan, not live permissions. Partial discovery, missing parent nodes and individual resource scopes can limit actual coverage.'
Add-Line ''
Add-Line '## 5. Full evidence register for tickets and validation'
Add-Line ''
Add-Line 'One row represents one direct eligibility schedule instance valid at the scan. Full Azure IDs are included to support reproducible queries. Treat this table as restricted internal evidence.'
Add-Line ''
Add-Line '| Role / priority | Principal ID / type | Exact grant scope | Schedule ID | Role definition ID | End date | Activation MFA | Auth context / ID | Approval | Justification | Max activation | PIM policy ID |'
Add-Line '|---|---|---|---|---|---|---|---|---|---|---|---|'
foreach ($record in $sortedRecords) {
    $raw = $record.Entry
    $contextValue = $record.Context
    if ($record.ContextId) { $contextValue += (' (' + $record.ContextId + ')') }
    $evidenceCells = @(
        (Escape-Md (Get-Field $raw 'Role')),
        $record.Tier,
        (Get-Field $raw 'PrincipalId'),
        (Escape-Md (Get-Field $raw 'PrincipalType')),
        (Escape-Md (Get-Field $raw 'AssignmentScope')),
        (Escape-Md (Get-Field $raw 'ScheduleId')),
        (Escape-Md (Get-Field $raw 'RoleDefinitionId')),
        (Escape-Md (Get-Field $raw 'EndDateTime')),
        $record.Mfa,
        (Escape-Md $contextValue),
        $record.Approval,
        $record.Justification,
        (Escape-Md $record.ActivationMax),
        (Escape-Md $record.PolicyId)
    )
    Add-Line ('| {0} ({1}) | `{2}` / {3} | `{4}` | `{5}` | `{6}` | {7} | {8} | {9} | {10} | {11} | {12} | `{13}` |' -f $evidenceCells)
}
Add-Line ''
if ($overlapNotes.Count -gt 0) {
    Add-Line '### Direct parent/child assignment overlaps to review'
    Add-Line ''
    Add-Line 'These are not inherited copies. The same principal and role have separate direct eligibility records at ancestor and descendant scopes. Investigate whether both are needed before changing either.'
    Add-Line ''
    Add-Line '| Principal | Role | Parent grant scope | Child direct grant scope |'
    Add-Line '|---|---|---|---|'
    foreach ($pair in $overlapNotes) {
        Add-Line ('| `{0}` | {1} | `{2}` | `{3}` |' -f (Get-Field $pair.Child.Entry 'PrincipalId'),(Escape-Md (Get-Field $pair.Child.Entry 'Role')),(Escape-Md (Get-Field $pair.Parent.Entry 'AssignmentScope')),(Escape-Md (Get-Field $pair.Child.Entry 'AssignmentScope')))
    }
    Add-Line ''
}
if ($failedScopes.Count -gt 0) {
    Add-Line '### Failed or incomplete Azure scope queries'
    Add-Line ''
    Add-Line '| Scope ID | Eligible API | Active schedule API |'
    Add-Line '|---|---|---|'
    foreach ($failure in $failedScopes) { Add-Line ('| `{0}` | {1} | {2} |' -f (Escape-Md (Get-Field $failure 'ScopeId')),(Escape-Md (Get-Field $failure 'Eligible')),(Escape-Md (Get-Field $failure 'ActiveSchedule'))) }
    Add-Line ''
}
Add-Line '### Input evidence and method'
Add-Line ''
Add-Line '- `pim_eligible_assignments.csv`: exact eligible schedule grants, principals, role definitions, original scopes and validity dates.'
Add-Line '- `observed_scope_hierarchy.csv`: management group, subscription and resource group ancestry observed by the scan.'
Add-Line '- `scan_status.csv`: success/failure and collected direct eligibility counts for each scanned scope.'
Add-Line '- `policy_settings.csv`: policy inventory joined on exact `ScopeId + RoleGuid`; this report does not inherit settings from parents.'
Add-Line '- This is a fully offline post-processing report. No Azure, Microsoft Graph or new consent was required.'
Add-Line ''
Add-Line 'Microsoft documentation: [PIM settings for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-resource-roles-configure-role-settings), [eligible Azure RBAC assignments](https://learn.microsoft.com/en-us/azure/role-based-access-control/pim-integration), [role assignment scopes](https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview).'

$outputPath = Join-Path $outRoot 'Azure-PIM-Hierarchy-MFA-Review.md'
$script:ReportLines.ToArray() | Set-Content -LiteralPath $outputPath -Encoding utf8 -ErrorAction Stop

# A short review register is convenient for filtered action tickets, but the
# Markdown report is self-contained and keeps the exact source evidence.
$exported = @($sortedRecords | ForEach-Object {
    $record = $_
    [pscustomobject]@{
        Role=Get-Field $record.Entry 'Role'; Tier=$record.Tier; ScopeKind=$record.Kind
        PrincipalId=Get-Field $record.Entry 'PrincipalId'; PrincipalType=Get-Field $record.Entry 'PrincipalType'
        AssignmentScope=Get-Field $record.Entry 'AssignmentScope'
        ObservedSubscriptions=$record.Reach.Subscriptions
        ScheduleId=Get-Field $record.Entry 'ScheduleId'
        RoleDefinitionId=Get-Field $record.Entry 'RoleDefinitionId'
        EndDateTime=Get-Field $record.Entry 'EndDateTime'
        PIM_MFA=$record.Mfa; PIM_AuthenticationContext=$record.Context
        PIM_AuthenticationContextId=$record.ContextId
        PIM_Approval=$record.Approval; PIM_MaxActivation=$record.ActivationMax
        PolicyId=$record.PolicyId; PolicyAssessment=$record.RuleState
    }
})
if ($exported.Count -gt 0) {
    $exported | Export-Csv -LiteralPath (Join-Path $outRoot 'Azure-PIM-Hierarchy-Review-Register.csv') -Encoding utf8 -NoTypeInformation
}
Write-Host "New Markdown report: $outputPath" -ForegroundColor Green
Write-Host "Direct eligibilities valid at scan: $($atScan.Count); policy matches $matchedCount; without explicit activation MFA/context $noBothCount; broad privileged $($highLevel.Count)." -ForegroundColor Cyan
Write-Host 'Existing reports and source CSVs were not changed. No Azure or Microsoft Graph calls were made.' -ForegroundColor Cyan
