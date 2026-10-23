#requires -Version 7.0
<#
.SYNOPSIS
  Produce a separate Confluence Markdown review of Azure resource PIM assignees and eligibility expiry.
.DESCRIPTION
  Uses the existing pim_eligible_assignments.csv. Does not change existing reports or CSVs.
  By default works entirely offline. Use -VerifyWithArm to make targeted read-only
  GET requests for each unique eligibility schedule instance and its parent schedule.
  These ARM responses can include the principal's display name and type, and can
  confirm whether the saved schedule exposes an end date. No Graph permissions.

  Group membership and PIM for Groups are NOT resolved. PrincipalType describes
  the object to which the Azure PIM role eligibility is assigned, not the people
  belonging to an assigned group.
.EXAMPLE
  .\New-AzurePimAssigneeExpiryReview.ps1 -ScopeAuditDirectory '.\PIMScopeAudit'
.EXAMPLE
  Connect-AzAccount -Tenant '<tenant-guid>'
  .\New-AzurePimAssigneeExpiryReview.ps1 -ScopeAuditDirectory '.\PIMScopeAudit' -VerifyWithArm
#>
[CmdletBinding()]
param(
    [string] $ScopeAuditDirectory = '.\PIMScopeAudit',
    [string] $OutputDirectory,
    [switch] $VerifyWithArm
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-Column {
    param([object] $Record, [string] $Column)
    if ($null -eq $Record) { return '' }
    $property = $Record.PSObject.Properties[$Column]
    if ($null -eq $property -or $null -eq $property.Value) { return '' }
    return [string] $property.Value
}
function Read-ObjectProperty {
    param([object] $Record, [string] $PropertyName)
    if ($null -eq $Record) { return $null }
    $item = $Record.PSObject.Properties[$PropertyName]
    if ($null -eq $item) { return $null }
    return $item.Value
}
function Format-MarkdownValue {
    param([object] $Value)
    $plain = [string] $Value
    if ([string]::IsNullOrWhiteSpace($plain)) { return 'Not recorded' }
    return $plain.Replace('|','\|').Replace("`r", ' ').Replace("`n", ' ').Replace('`','')
}
function Invoke-ReadOnlyArmGet {
    param([string] $ResourceId)
    if ($ResourceId -notmatch '(?i)^/(providers/Microsoft\.Management/managementGroups/[^/]+|subscriptions/[^/]+(?:/resourceGroups/[^/]+)?)/providers/Microsoft\.Authorization/roleEligibilitySchedule(?:Instances|s)/[^/?#]+$') {
        throw 'The saved schedule ID is not a supported ARM eligibility schedule resource path.'
    }
    $requestPath = $ResourceId + '?api-version=2020-10-01'
    $reply = Invoke-AzRestMethod -Method GET -Path $requestPath -ErrorAction Stop
    if ([int] $reply.StatusCode -ne 200) {
        throw "ARM returned HTTP $($reply.StatusCode) for $ResourceId"
    }
    return ConvertFrom-Json -InputObject $reply.Content -Depth 100
}
function Get-ExpiryAssessment {
    param([string] $InstanceEnd, [string] $ScheduleEnd, [string] $ArmState)
    $effectiveEnd = if ($InstanceEnd) { $InstanceEnd } else { $ScheduleEnd }
    if ($effectiveEnd) {
        if ($effectiveEnd -match '^9999-') { return 'No effective expiry (sentinel end date: verify)' }
        if ($InstanceEnd -and $ScheduleEnd -and $InstanceEnd -ne $ScheduleEnd) {
            return 'End dates disagree between instance and schedule: review'
        }
        return 'Time-bound eligibility (end date recorded)'
    }
    if ($ArmState -eq 'Both schedule reads succeeded') {
        return 'No end date in instance or parent schedule (consistent with permanent eligibility)'
    }
    if ($ArmState -eq 'Instance read succeeded; schedule unavailable') {
        return 'No end date in instance; parent schedule unverified'
    }
    return 'No end date in CSV; not independently verified'
}

$sourceDirectory = (Resolve-Path -LiteralPath $ScopeAuditDirectory -ErrorAction Stop).Path
$sourcePath = Join-Path $sourceDirectory 'pim_eligible_assignments.csv'
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "Missing saved eligibility evidence: $sourcePath"
}
$allEvidence = @(Import-Csv -LiteralPath $sourcePath -ErrorAction Stop)
if (-not $allEvidence.Count) { throw "Eligibility CSV is empty: $sourcePath" }
foreach ($necessary in @('PrincipalId','PrincipalType','Role','AssignmentScope','ScheduleId','EndDateTime','Status')) {
    if ($necessary -notin $allEvidence[0].PSObject.Properties.Name) {
        throw "CSV is missing expected column '$necessary'. Expected the export from Get-AzurePimScopeEvidence-v3.ps1."
    }
}

if (-not $OutputDirectory) { $OutputDirectory = Join-Path $sourceDirectory 'AssigneeExpiryReview' }
[void] (New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop)
$destination = (Resolve-Path -LiteralPath $OutputDirectory).Path

if ($VerifyWithArm) {
    Import-Module Az.Accounts -ErrorAction Stop
    if (-not (Get-AzContext)) {
        throw 'Use Connect-AzAccount in the correct tenant before -VerifyWithArm. No Graph permissions are requested.'
    }
}
$directCurrent = @($allEvidence | Where-Object {
    (Read-Column $_ 'Status') -eq 'Current' -and
    (Read-Column $_ 'MemberType') -ne 'Inherited'
})
$unique = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$records = [System.Collections.Generic.List[object]]::new()
$duplicates = 0
foreach ($record in $directCurrent) {
    $identity = Read-Column $record 'ScheduleId'
    if (-not $identity) {
        $identity = ('{0}|{1}|{2}|{3}' -f (Read-Column $record 'PrincipalId'),(Read-Column $record 'RoleDefinitionId'),(Read-Column $record 'AssignmentScope'),(Read-Column $record 'StartDateTime'))
    }
    if (-not $unique.Add($identity)) { $duplicates++; continue }
    $principalType = Read-Column $record 'PrincipalType'
    $instanceExpiry = Read-Column $record 'EndDateTime'
    $scheduleExpiry = ''
    $principalName = ''
    $principalEmail = ''
    $parentScheduleId = ''
    $armState = 'Offline: ARM not queried'
    $readError = ''
    $evidenceSource = 'Saved eligible schedule instance CSV'
    if ($VerifyWithArm) {
        try {
            $instance = Invoke-ReadOnlyArmGet -ResourceId (Read-Column $record 'ScheduleId')
            $properties = Read-ObjectProperty $instance 'properties'
            $armState = 'Instance read succeeded; schedule unavailable'
            $evidenceSource = 'Current ARM eligibility instance'
            if ($null -ne $properties) {
                $returnedType = [string] (Read-ObjectProperty $properties 'principalType')
                if ($returnedType) { $principalType = $returnedType }
                $expanded = Read-ObjectProperty $properties 'expandedProperties'
                $principal = Read-ObjectProperty $expanded 'principal'
                if ($null -ne $principal) {
                    $principalName = [string] (Read-ObjectProperty $principal 'displayName')
                    $principalEmail = [string] (Read-ObjectProperty $principal 'email')
                    if (-not $principalType) { $principalType = [string] (Read-ObjectProperty $principal 'type') }
                }
                $instanceExpiry = [string] (Read-ObjectProperty $properties 'endDateTime')
                $parentScheduleId = [string] (Read-ObjectProperty $properties 'roleEligibilityScheduleId')
            }
            if ($parentScheduleId) {
                try {
                    $parentSchedule = Invoke-ReadOnlyArmGet -ResourceId $parentScheduleId
                    $parentProperties = Read-ObjectProperty $parentSchedule 'properties'
                    $scheduleExpiry = [string] (Read-ObjectProperty $parentProperties 'endDateTime')
                    $armState = 'Both schedule reads succeeded'
                    $evidenceSource = 'Current ARM eligibility instance and parent schedule'
                    if (-not $principalName) {
                        $parentExpanded = Read-ObjectProperty $parentProperties 'expandedProperties'
                        $parentPrincipal = Read-ObjectProperty $parentExpanded 'principal'
                        if ($null -ne $parentPrincipal) {
                            $principalName = [string] (Read-ObjectProperty $parentPrincipal 'displayName')
                            $principalEmail = [string] (Read-ObjectProperty $parentPrincipal 'email')
                        }
                    }
                }
                catch {
                    $readError = 'Parent schedule lookup: ' + $_.Exception.Message
                }
            }
        }
        catch {
            $armState = 'Instance read failed; saved CSV retained'
            $readError = 'Eligibility instance lookup: ' + $_.Exception.Message
            $instanceExpiry = Read-Column $record 'EndDateTime'
        }
    }
    if (-not $principalType) { $principalType = 'Unresolved' }
    $expiryAssessment = Get-ExpiryAssessment -InstanceEnd $instanceExpiry -ScheduleEnd $scheduleExpiry -ArmState $armState
    $expiryDisplay = if ($instanceExpiry) { $instanceExpiry } elseif ($scheduleExpiry) { $scheduleExpiry } else { 'No end date returned' }
    [void]$records.Add([pscustomobject][ordered]@{
        Role=(Read-Column $record 'Role')
        Tier=(Read-Column $record 'Tier')
        ScopeKind=(Read-Column $record 'ScopeKind')
        ScopePath=(Read-Column $record 'ScopePath')
        AssignmentScope=(Read-Column $record 'AssignmentScope')
        PrincipalType=$principalType
        PrincipalName=$principalName
        PrincipalEmail=$principalEmail
        PrincipalId=(Read-Column $record 'PrincipalId')
        MemberType=(Read-Column $record 'MemberType')
        StartDateTime=(Read-Column $record 'StartDateTime')
        EndDateTime=$expiryDisplay
        ExpiryAssessment=$expiryAssessment
        SourceEndDateTime=(Read-Column $record 'EndDateTime')
        ArmInstanceEndDateTime=$instanceExpiry
        ArmScheduleEndDateTime=$scheduleExpiry
        ScheduleId=(Read-Column $record 'ScheduleId')
        ParentScheduleId=$parentScheduleId
        ArmVerification=$armState
        EvidenceSource=$evidenceSource
        ReadError=$readError
    })
}

$out = @($records.ToArray() | Sort-Object @{Expression={
    $tier = $_.Tier
    switch ($tier) { 'Critical' {0}; 'Elevated' {1}; 'Unclassified' {2}; default {3} }
}}, @{Expression={
    switch ($_.ScopeKind) { 'ManagementGroup' {0}; 'Subscription' {1}; 'ResourceGroup' {2}; default {3} }
}}, Role, AssignmentScope, PrincipalId)
$registerPath = Join-Path $destination 'Azure-PIM-Assignee-Expiry-Register.csv'
if ($out.Count -gt 0) {
    $out | Export-Csv -LiteralPath $registerPath -NoTypeInformation -Encoding utf8 -ErrorAction Stop
} else {
    'Role,PrincipalId,ExpiryAssessment' | Set-Content -LiteralPath $registerPath -Encoding utf8
}

$groupPrincipals = @($out | Where-Object { $_.PrincipalType -in @('Group','ForeignGroup') })
$users = @($out | Where-Object PrincipalType -eq 'User')
$groupDerived = @($out | Where-Object MemberType -eq 'Group')
$unresolved = @($out | Where-Object PrincipalType -eq 'Unresolved')
$noDate = @($out | Where-Object { $_.EndDateTime -eq 'No end date returned' })
$longScope = @($out | Where-Object { $_.Tier -in @('Critical','Elevated') -and $_.ScopeKind -in @('ManagementGroup','Subscription') })
$failures = @($out | Where-Object { $_.ReadError })

$lines = [System.Collections.Generic.List[string]]::new()
function Add-ReportLine { param([string] $Value = '') [void]$script:lines.Add($Value) }
Add-ReportLine '# Azure resource PIM: who is eligible and when eligibility ends'
Add-ReportLine ''
Add-ReportLine ('**Source:** `pim_eligible_assignments.csv` from the existing Azure scope audit. **Mode:** {0}. **Status:** evidence review, not a live access certification.' -f $(if($VerifyWithArm){'Targeted Azure Resource Manager verification'}else{'Offline, from saved evidence only'}))
Add-ReportLine ''
Add-ReportLine ('**{0} direct, currently effective eligibility records**, from {1} CSV records. {2} duplicate schedule records excluded.' -f $out.Count,$allEvidence.Count,$duplicates)
Add-ReportLine ''
Add-ReportLine ('- **{0} with no end date returned**. {1}' -f $noDate.Count, $(if($VerifyWithArm){'Check the individual expiry assessments below for ARM verification status.'}else{'This is not conclusive evidence of permanent eligibility until checked against the ARM schedule.'}))
Add-ReportLine ('- **{0} assigned to individual users; {1} assigned to groups; {2} unresolved principal types**.' -f $users.Count,$groupPrincipals.Count,$unresolved.Count)
Add-ReportLine ('- **{0} additional records indicate `MemberType=Group`**, which can describe a group-derived membership route even when the principal object is a user.' -f $groupDerived.Count)
Add-ReportLine ('- **{0} Critical/Elevated role eligibilities assigned directly at management group or subscription scope**.' -f $longScope.Count)
if ($failures.Count -gt 0) { Add-ReportLine ('- **{0} ARM lookups did not complete**. Do not treat missing details as empty or permanent.' -f $failures.Count) }
Add-ReportLine ''
Add-ReportLine '## 1. Broad privileged eligibility'
Add-ReportLine ''
Add-ReportLine 'These rows deserve scope, principal and expiry review. Broad assignment is not automatically inappropriate. Group membership is not expanded in this report.'
Add-ReportLine ''
Add-ReportLine '| Role | Grant scope | Assigned to | Principal ID | Eligibility end | Evidence assessment |'
Add-ReportLine '|---|---|---|---|---|---|'
if (-not $longScope.Count) { Add-ReportLine '| None in collected direct eligibilities | | | | | |' }
foreach ($grant in $longScope) {
    $personLabel = if ($grant.PrincipalName) { $grant.PrincipalName + ' (' + $grant.PrincipalType + ')' } else { $grant.PrincipalType }
    Add-ReportLine ('| {0} | {1} | {2} | `{3}` | {4} | {5} |' -f (Format-MarkdownValue $grant.Role),(Format-MarkdownValue $grant.AssignmentScope),(Format-MarkdownValue $personLabel),(Format-MarkdownValue $grant.PrincipalId),(Format-MarkdownValue $grant.EndDateTime),(Format-MarkdownValue $grant.ExpiryAssessment))
}
Add-ReportLine ''
Add-ReportLine '## 2. Eligibilities assigned to groups'
Add-ReportLine ''
if (-not $groupPrincipals.Count) {
    Add-ReportLine 'None of the saved **current, direct** eligibility rows identify their principal type as Group or ForeignGroup. Unresolved principal types still need checking.'
} else {
    Add-ReportLine '| Role | Group name (when resolved) | Group object ID | Scope | End date | Schedule instance |'
    Add-ReportLine '|---|---|---|---|---|---|'
    foreach ($grant in $groupPrincipals) {
        Add-ReportLine ('| {0} | {1} | `{2}` | {3} | {4} | `{5}` |' -f (Format-MarkdownValue $grant.Role),(Format-MarkdownValue $grant.PrincipalName),(Format-MarkdownValue $grant.PrincipalId),(Format-MarkdownValue $grant.AssignmentScope),(Format-MarkdownValue $grant.EndDateTime),(Format-MarkdownValue $grant.ScheduleId))
    }
}
Add-ReportLine ''
Add-ReportLine '**Membership remains unverified.** A group principal tells us which Entra group holds Azure role eligibility, not which users belong to it or whether group membership is itself governed through PIM for Groups. That requires separate Entra directory evidence.'
if ($groupDerived.Count) {
    Add-ReportLine ''
    Add-ReportLine ('**Group-derived membership records:** {0} have `MemberType=Group`. These are not necessarily direct grants to a Group principal. Their source group is not established by this export.' -f $groupDerived.Count)
}
Add-ReportLine ''
Add-ReportLine '## 3. Full direct eligibility evidence'
Add-ReportLine ''
Add-ReportLine '| Role | Principal name or type | Principal ID | Direct scope | Start | End | Expiry assessment | Schedule ID |'
Add-ReportLine '|---|---|---|---|---|---|---|---|'
if (-not $out.Count) { Add-ReportLine '| No current, direct eligibilities in the saved records | | | | | | | |' }
foreach ($grant in $out) {
    $principalLabel = if ($grant.PrincipalName) { $grant.PrincipalName + ' (' + $grant.PrincipalType + ')' } else { $grant.PrincipalType }
    Add-ReportLine ('| {0} | {1} | `{2}` | {3} | {4} | {5} | {6} | `{7}` |' -f (Format-MarkdownValue $grant.Role),(Format-MarkdownValue $principalLabel),(Format-MarkdownValue $grant.PrincipalId),(Format-MarkdownValue $grant.AssignmentScope),(Format-MarkdownValue $grant.StartDateTime),(Format-MarkdownValue $grant.EndDateTime),(Format-MarkdownValue $grant.ExpiryAssessment),(Format-MarkdownValue $grant.ScheduleId))
}
Add-ReportLine ''
Add-ReportLine '## 4. How to interpret the results'
Add-ReportLine ''
Add-ReportLine '- **No end date returned** is an observation, not proof of permanent eligibility. If the current schedule and instance both have no end date, permanent eligibility is plausible; confirm the business-approved duration.'
Add-ReportLine '- **PrincipalType = User** identifies an individual object, **Group/ForeignGroup** a group, and **Unresolved** means this audit cannot classify the principal reliably.'
Add-ReportLine '- **MemberType = Group** describes a membership route in the API. It is not interchangeable with PrincipalType and should not be used to count group principals.'
Add-ReportLine '- **Eligible** is not the same as **currently active**. Active RBAC and PIM activation schedules are in separate CSV files and are deliberately excluded here.'
Add-ReportLine '- This only covers Azure resource PIM eligibilities in the scopes already scanned; it does not enumerate members of an assigned group or Microsoft Entra directory role PIM.'
Add-ReportLine '- Any unresolved scope coverage and privileged-role activation safeguards should be taken from the existing scope audit and hierarchy/MFA review.'
Add-ReportLine ''
Add-ReportLine '## 5. Evidence sources and closure'
Add-ReportLine ''
Add-ReportLine '- Source: `pim_eligible_assignments.csv` (principal, principal type, role, grant scope, schedule ID, start and end dates).'
if ($VerifyWithArm) { Add-ReportLine '- Verification: current ARM `roleEligibilityScheduleInstances/{id}` and, when available, parent `roleEligibilitySchedules/{id}`. Individual failures are recorded in the CSV register.' }
Add-ReportLine '- For each broad privileged assignment: confirm principal owner, necessity of scope, expiry or permanent-eligibility approval, group members if applicable, and the matching PIM activation policy.'
Add-ReportLine '- Preserve exact schedule IDs in the review ticket, and confirm remediation with a new targeted read once changes are authorised.'
Add-ReportLine ''
Add-ReportLine 'Microsoft API reference: https://learn.microsoft.com/en-us/rest/api/authorization/role-eligibility-schedule-instances/get?view=rest-authorization-2020-10-01'

$reportPath = Join-Path $destination 'Azure-PIM-Assignee-Expiry-Review.md'
$lines.ToArray() | Set-Content -LiteralPath $reportPath -Encoding utf8 -ErrorAction Stop
Write-Host "Assignee/expiry Markdown report: $reportPath" -ForegroundColor Green
Write-Host "Evidence CSV: $registerPath" -ForegroundColor Green
Write-Host "Current direct eligibilities: $($out.Count); groups: $($groupPrincipals.Count); no end date: $($noDate.Count); ARM failures: $($failures.Count)." -ForegroundColor Cyan
Write-Host 'The original reports and evidence CSVs were not modified.' -ForegroundColor Cyan
