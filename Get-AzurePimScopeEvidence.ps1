#requires -Version 7.0
<#
.SYNOPSIS
  Audit where Azure resource PIM eligibility is granted and how far it reaches.
.DESCRIPTION
  Read-only Azure Resource Manager collection with a Confluence Markdown report.
  Separates PIM eligibility, active PIM schedule instances and optional ordinary
  RBAC role grants. Uses existing Az.Accounts login, not Microsoft Graph.

  This is an assignment-scope audit, NOT a PIM role-policy audit. Optionally join
  policy_settings.csv produced by Analyse-AzurePimPartial-v2.ps1.

  Default scope is management groups and subscriptions. To capture assignments
  made directly on resource groups, select -ScopeDepth ResourceGroups. The latter
  cannot prove there are no assignments at individual resource scope.

  Output includes precise principal/role/scope/schedule IDs and completeness
  status. Missing, inaccessible and failed scopes are never recorded as empty.
.EXAMPLE
  Connect-AzAccount -Tenant '<tenant-id>'
  .\Get-AzurePimScopeEvidence.ps1 -ManagementGroupId '<management-group-id>' `
      -PolicySettingsCsv '.\AzurePimReport\PimAnalysis_20261022_093616\policy_settings.csv'
.EXAMPLE
  .\Get-AzurePimScopeEvidence.ps1 -ReportOnly -OutputDirectory '.\PimScopeAudit' `
      -PolicySettingsCsv '.\AzurePimReport\PimAnalysis_20261022_093616\policy_settings.csv'
.EXAMPLE
  .\Get-AzurePimScopeEvidence.ps1 -SubscriptionId (Get-AzContext).Subscription.Id `
      -ScopeDepth ResourceGroups -IncludeCurrentRbac -OutputDirectory 'C:\Temp\PimScopeAudit'
.NOTES
  Requires PowerShell 7 and Az.Accounts. This script makes only GET requests.
  Use -ReportOnly -OutputDirectory <existing CSV folder> to regenerate Markdown
  entirely offline without importing Az.Accounts or making any Azure requests.
  -ReportOnly never overwrites the source CSV files.
  Uses ARM 2020-10-01 schedule APIs, ARM 2022-04-01 RBAC/role-definition APIs,
  ARM 2020-05-01 management-group API and ARM 2021-04-01 resource-group API.
  Restrict access to evidence exports containing principal IDs and scope paths.
#>
[CmdletBinding()]
param(
    [string] $ManagementGroupId,
    [string] $SubscriptionId,
    [ValidateSet('ManagementGroupsAndSubscriptions','ResourceGroups')]
    [string] $ScopeDepth = 'ManagementGroupsAndSubscriptions',
    [string] $PolicySettingsCsv,
    [switch] $IncludeCurrentRbac,
    [switch] $ReportOnly,
    [switch] $SkipRoleDefinitionLookup,
    [ValidateRange(1, 2000)][int] $MaxRoleLookups = 200,
    [ValidateRange(1, 100)][int] $Examples = 25,
    [string] $OutputDirectory = (Join-Path (Get-Location).Path 'PimScopeAudit')
)
$ErrorActionPreference = 'Stop'
if (-not $ReportOnly) {
    Import-Module Az.Accounts -ErrorAction Stop
    $ctx = Get-AzContext
    if (-not $ctx -or -not $ctx.Tenant -or -not $ctx.Tenant.Id) {
        throw 'Connect to the correct tenant with Connect-AzAccount before running.'
    }
    if ($ManagementGroupId -and $SubscriptionId) { throw 'Supply either -ManagementGroupId or -SubscriptionId, not both.' }
    if (-not $ManagementGroupId -and -not $SubscriptionId) { $ManagementGroupId = [string] $ctx.Tenant.Id }
    if ($SubscriptionId -and $SubscriptionId -notmatch '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        throw 'SubscriptionId must be a GUID, without the /subscriptions/ prefix.'
    }
} else {
    if ($ManagementGroupId -or $SubscriptionId) {
        throw 'In -ReportOnly mode the observed starting scopes come from observed_scope_hierarchy.csv; omit -ManagementGroupId and -SubscriptionId.'
    }
    # Tenant ID and precise scan start time were not included in the CSV exports.
    $ctx = [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = 'Not recorded in saved CSVs' } }
}
if (-not $ReportOnly) {
    [void](New-Item -ItemType Directory -Path $OutputDirectory -Force)
} elseif (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    throw "ReportOnly requires the EXISTING scan output directory, which was not found: $OutputDirectory"
}
$dest = (Resolve-Path -LiteralPath $OutputDirectory).Path
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$asOf = [datetime]::UtcNow
$timingLabel = if ($ReportOnly) {'Source file last modified (UTC)'} else {'Evidence captured (UTC)'}
$startLabel = if ($ReportOnly) {'From saved hierarchy'} elseif ($SubscriptionId) {"/subscriptions/$SubscriptionId"} else {$ManagementGroupId}

$script:Nodes = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$script:Eligible = [System.Collections.Generic.List[object]]::new()
$script:Active = [System.Collections.Generic.List[object]]::new()
$script:Rbac = [System.Collections.Generic.List[object]]::new()
$script:Failures = [System.Collections.Generic.List[object]]::new()
$script:ScopesStatus = [System.Collections.Generic.List[object]]::new()
$script:RoleCache = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$script:RoleLookupCount = 0
$script:SeenEvidence = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

function Get-Text { param($Obj, [string] $Name)
    if ($null -eq $Obj) { return '' }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return '' }
    return [string] $p.Value
}
function Normalise-Scope { param([string]$Scope)
    if ([string]::IsNullOrWhiteSpace($Scope)) { return '' }
    return $Scope.Trim().TrimEnd('/')
}
function Scope-Type { param([string]$Scope)
    if ($Scope -match '(?i)^/providers/Microsoft.Management/managementGroups/[^/]+$') { return 'ManagementGroup' }
    if ($Scope -match '(?i)^/subscriptions/[^/]+$') { return 'Subscription' }
    if ($Scope -match '(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return 'ResourceGroup' }
    if (-not $Scope) { return 'Unresolved' }
    return 'ResourceOrOther'
}
function Append-Failure { param([string]$Scope, [string]$Operation, [string]$Message)
    $record = [pscustomobject]@{ ScopeId=$Scope; Operation=$Operation; Error=$Message }
    [void]$script:Failures.Add($record)
    Write-Warning "[$Operation] ${Scope}: $Message"
}
function Invoke-ArmRead { param([Parameter(Mandatory)][string]$Path)
    if ($Path -match '^https?://') {
        $uri = [uri] $Path
        if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'management.azure.com') {
            throw "Refusing ARM continuation from unexpected host: $Path"
        }
    }
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            if ($Path -match '^https://') {
                $reply = Invoke-AzRestMethod -Method GET -Uri $Path -ErrorAction Stop
            } else {
                $reply = Invoke-AzRestMethod -Method GET -Path $Path -ErrorAction Stop
            }
            $status = [int] $reply.StatusCode
            if (($status -eq 429 -or $status -ge 500) -and $attempt -lt 4) {
                Start-Sleep -Seconds ([int][math]::Pow(2, $attempt))
                continue
            }
            if ($status -lt 200 -or $status -ge 300) {
                $reason = [string] $reply.Content
                if ($reason.Length -gt 600) { $reason = $reason.Substring(0,600) }
                throw "HTTP $status : $reason"
            }
            if ([string]::IsNullOrWhiteSpace([string]$reply.Content)) { return $null }
            return ConvertFrom-Json -InputObject $reply.Content -Depth 100
        }
        catch {
            $message = $_.Exception.Message
            if ($attempt -lt 4 -and $message -match '(?i)(429|TooManyRequests|throttl|\b50[0234]\b|timed?\s*out|timeout|connection\s+(?:reset|closed)|taskcanceled)') {
                Start-Sleep -Seconds ([int][math]::Pow(2, $attempt))
                continue
            }
            throw "ARM GET $Path failed: $message"
        }
    }
}
function Get-ArmItems { param([Parameter(Mandatory)][string] $Path)
    $next = $Path
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    while ($next) {
        if (-not $seen.Add($next)) { throw "ARM pagination repeated continuation: $next" }
        $res = Invoke-ArmRead -Path $next
        if ($null -eq $res -or $null -eq $res.PSObject.Properties['value']) {
            throw "ARM list response missing 'value': $next"
        }
        foreach ($item in @($res.value)) { if ($null -ne $item) { Write-Output $item } }
        $next = [string] $res.nextLink
    }
}
function Add-Node { param([string]$Id,[string]$Name,[string]$ParentId = '')
    $Id = Normalise-Scope $Id
    $ParentId = Normalise-Scope $ParentId
    if (-not $Id) { return }
    if ($script:Nodes.ContainsKey($Id)) { return }
    $kind = Scope-Type $Id
    [void]$script:Nodes.Add($Id, [pscustomobject]@{
        ScopeId=$Id; ScopeName=$(if($Name){$Name}else{($Id -split '/')[-1]});
        Kind=$kind; ParentId=$ParentId
    })
}
function Add-HierarchyChildren { param($Children,[string]$ParentId)
    foreach ($child in @($Children)) {
        if ($null -eq $child -or -not $child.id) { continue }
        $childId = Normalise-Scope ([string]$child.id)
        if ((Scope-Type $childId) -notin @('ManagementGroup','Subscription')) { continue }
        Add-Node -Id $childId -Name ([string]$child.displayName) -ParentId $ParentId
        if ((Scope-Type $childId) -eq 'ManagementGroup') {
            Add-HierarchyChildren -Children $child.children -ParentId $childId
        }
    }
}
function Hierarchy-Path { param([string]$Scope)
    $parts = [System.Collections.Generic.List[string]]::new()
    $cursor = Normalise-Scope $Scope
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    while ($cursor -and $script:Nodes.ContainsKey($cursor) -and $seen.Add($cursor)) {
        $n = $script:Nodes[$cursor]
        $parts.Insert(0, [string]$n.ScopeName)
        $cursor = [string]$n.ParentId
    }
    if ($parts.Count -eq 0) { return $Scope }
    return ($parts.ToArray() -join ' / ')
}
function Child-Counts { param([string]$Scope)
    $subCount = 0; $rgCount = 0
    foreach ($node in $script:Nodes.Values) {
        $cursor = [string]$node.ParentId
        $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        while ($cursor -and $visited.Add($cursor) -and $script:Nodes.ContainsKey($cursor)) {
            if ($cursor -ieq $Scope) {
                if ($node.Kind -eq 'Subscription') { $subCount++ }
                elseif ($node.Kind -eq 'ResourceGroup') { $rgCount++ }
                break
            }
            $cursor = [string] $script:Nodes[$cursor].ParentId
        }
    }
    return [pscustomobject]@{ Subscriptions=$subCount; ResourceGroups=$rgCount }
}
function Get-Priority { param([string]$Guid, [string]$Name)
    switch ($Guid.ToLowerInvariant()) {
        '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' { return 'Critical' } # Owner
        '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' { return 'Critical' } # UAA
        'f58310d9-a9f6-439a-9e8d-f62e7b41a168' { return 'Critical' } # RBAC Admin
        'b24988ac-6180-42a0-ab88-20f7382dd24c' { return 'Elevated' } # Contributor
        'acdd72a7-3385-48ef-bd42-f606fba81ae7' { return 'Lower' } # Reader
    }
    if ($Name -match '(?i)^(Key Vault Administrator|Storage Blob Data Owner|Azure Kubernetes Service RBAC Cluster Admin|Security Admin|Security Administrator)$') { return 'Elevated' }
    if ($Name -match '(?i)^.*(Administrator|Admin|Owner|Contributor|Operator).*$') { return 'Elevated' }
    if ($Name -match '(?i)^(Reader|Monitoring Reader|Security Reader)$') { return 'Lower' }
    return 'Unclassified'
}
function Get-Role { param([string]$DefinitionId, [string]$EmbeddedName)
    $guid = ([string]$DefinitionId -split '/')[-1].ToLowerInvariant()
    if (-not $guid) { return [pscustomobject]@{RoleGuid='';RoleName='Unresolved';Tier='Unclassified'} }
    if ($script:RoleCache.ContainsKey($guid)) { return $script:RoleCache[$guid] }
    $known = @{
        '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
        '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
        'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
        'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
        'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
    }
    $name = $EmbeddedName
    $definitionType = ''
    if (-not $name -and $known.ContainsKey($guid)) { $name = $known[$guid] }
    # Names alone are not evidence that a tenant-defined custom role is low privilege.
    if (-not $known.ContainsKey($guid) -and -not $SkipRoleDefinitionLookup -and $script:RoleLookupCount -lt $MaxRoleLookups -and $DefinitionId -match '/providers/Microsoft.Authorization/roleDefinitions/') {
        $script:RoleLookupCount++
        try {
            $def = Invoke-ArmRead -Path ("{0}?api-version=2022-04-01" -f $DefinitionId)
            if ($def -and $def.properties.roleName) { $name = [string]$def.properties.roleName }
            if ($def -and $def.properties.type) { $definitionType = [string]$def.properties.type }
        }
        catch { Append-Failure -Scope $DefinitionId -Operation 'ResolveRoleName' -Message $_.Exception.Message }
    }
    if (-not $name) { $name = "Unresolved role ($guid)" }
    $tier = if ($definitionType -match '(?i)CustomRole') { 'Unclassified' }
            elseif (-not $known.ContainsKey($guid) -and -not $definitionType) { 'Unclassified' }
            else { Get-Priority -Guid $guid -Name $name }
    $result = [pscustomobject]@{RoleGuid=$guid;RoleName=$name;Tier=$tier;RoleDefinitionType=$definitionType}
    $script:RoleCache[$guid] = $result
    return $result
}
function Get-RecordDate { param($Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return '' }
    return [string] $Value
}
function Get-CurrentState { param([string]$Start,[string]$End)
    $date = [datetimeoffset]::MinValue
    if ($Start -and [datetimeoffset]::TryParse($Start,[ref]$date) -and $date.UtcDateTime -gt $asOf) { return 'Upcoming' }
    if ($End -and [datetimeoffset]::TryParse($End,[ref]$date) -and $date.UtcDateTime -lt $asOf) { return 'Expired' }
    return 'Current'
}
function Add-ScheduleRows { param([string]$QueryScope,[string]$Category,$Items)
    $added = 0
    foreach ($obj in @($Items)) {
        if ($null -eq $obj -or -not $obj.properties) { continue }
        $p = $obj.properties
        $assignedScope = Normalise-Scope ([string]$p.scope)
        # ARM atScope() can also include inherited assignments from parent scopes.
        # Collect only the direct grant at this scanned scope, to avoid inflating totals.
        if ($assignedScope -ine $QueryScope) { continue }
        $evidenceId = [string]$obj.id
        if (-not $evidenceId) { $evidenceId = [string]$obj.name }
        $dedupe = "${Category}|$evidenceId"
        if (-not $script:SeenEvidence.Add($dedupe)) { continue }
        $embeddedName = ''
        if ($p.expandedProperties -and $p.expandedProperties.roleDefinition) {
            $embeddedName = [string]$p.expandedProperties.roleDefinition.displayName
        }
        $role = Get-Role -DefinitionId ([string]$p.roleDefinitionId) -EmbeddedName $embeddedName
        $children = Child-Counts -Scope $assignedScope
        $state = Get-CurrentState -Start ([string]$p.startDateTime) -End ([string]$p.endDateTime)
        $apiStatus = [string]$p.status
        if ($apiStatus -match '^(Revoked|Denied|Canceled|Failed|Invalid)$') { $state = 'Not effective' }
        elseif ($apiStatus -match '^(Pending|PendingApproval|PendingProvisioning|PendingEvaluation)') { $state = 'Pending verification' }
        $record = [pscustomobject]@{
            EvidenceType=$Category; Status=$state; ApiStatus=$apiStatus
            PrincipalId=[string]$p.principalId; PrincipalType=[string]$p.principalType
            Role=$role.RoleName; RoleGuid=$role.RoleGuid; Tier=$role.Tier; RoleDefinitionType=$role.RoleDefinitionType
            ScopeKind=(Scope-Type $assignedScope); ScopeName=$script:Nodes[$assignedScope].ScopeName
            AssignmentScope=$assignedScope; ScopePath=(Hierarchy-Path -Scope $assignedScope)
            ObservedChildSubscriptions=$children.Subscriptions
            ObservedChildResourceGroups=$children.ResourceGroups
            ScheduleId=$evidenceId
            RoleDefinitionId=[string]$p.roleDefinitionId
            StartDateTime=Get-RecordDate $p.startDateTime
            EndDateTime=Get-RecordDate $p.endDateTime
            AssignmentType=$(if($Category -eq 'ActiveSchedule'){[string]$p.assignmentType}else{''})
            MemberType=[string]$p.memberType
            OriginRoleAssignmentId=[string]$p.originRoleAssignmentId
            LinkedRoleEligibilityScheduleId=[string]$p.linkedRoleEligibilityScheduleId
            Condition=[string]$p.condition
        }
        if ($Category -eq 'Eligible') { [void]$script:Eligible.Add($record) }
        else { [void]$script:Active.Add($record) }
        $added++
    }
    return $added
}
function Add-DirectRbacRows { param([string]$QueryScope,$Items)
    $added = 0
    foreach ($obj in @($Items)) {
        if ($null -eq $obj -or -not $obj.properties) { continue }
        $p = $obj.properties
        $assignedScope = Normalise-Scope ([string]$p.scope)
        if ($assignedScope -ine $QueryScope) { continue }
        $evidenceId = [string]$obj.id
        $dedupe = "Rbac|$evidenceId"
        if (-not $script:SeenEvidence.Add($dedupe)) { continue }
        $role = Get-Role -DefinitionId ([string]$p.roleDefinitionId) -EmbeddedName ''
        $children = Child-Counts -Scope $assignedScope
        [void]$script:Rbac.Add([pscustomobject]@{
            PrincipalId=[string]$p.principalId; PrincipalType=[string]$p.principalType
            Role=$role.RoleName; RoleGuid=$role.RoleGuid; Tier=$role.Tier; RoleDefinitionType=$role.RoleDefinitionType
            ScopeKind=(Scope-Type $assignedScope); ScopeName=$script:Nodes[$assignedScope].ScopeName
            AssignmentScope=$assignedScope; ScopePath=(Hierarchy-Path -Scope $assignedScope)
            ObservedChildSubscriptions=$children.Subscriptions
            ObservedChildResourceGroups=$children.ResourceGroups
            RoleAssignmentId=$evidenceId; Condition=[string]$p.condition
            CreatedOn=[string]$p.createdOn
            OriginClassification='Unverified (check assignment schedule)'
        })
        $added++
    }
    return $added
}
function ConvertTo-MarkdownCell { param($Value)
    $s = [string]$Value
    if (-not $s.Trim()) { return 'Not recorded' }
    $s = $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('|','\|').Replace("`r",' ').Replace("`n",' ').Replace('`','')
    return $s
}
function Export-Evidence { param([object[]]$Rows,[string]$File)
    if ($Rows.Count) { $Rows | Export-Csv -LiteralPath $File -NoTypeInformation -Encoding utf8 }
    else { 'No records found; check scan_status.csv to distinguish zero findings from failed coverage.' | Set-Content -LiteralPath ($File + '.empty.txt') -Encoding utf8 }
}

if (-not $ReportOnly) {
# Scope discovery. Do not silently infer access to all scopes from an incomplete hierarchy.
if ($SubscriptionId) {
    Add-Node -Id "/subscriptions/$SubscriptionId" -Name $SubscriptionId
} else {
    $path = '/providers/Microsoft.Management/managementGroups/{0}?api-version=2020-05-01&$expand=children&$recurse=true' -f [uri]::EscapeDataString($ManagementGroupId)
    try { $mg = Invoke-ArmRead -Path $path }
    catch { throw "Cannot enumerate starting management group '$ManagementGroupId': $($_.Exception.Message)" }
    $name = if ($mg.properties.displayName) { [string]$mg.properties.displayName } else { $ManagementGroupId }
    Add-Node -Id ([string]$mg.id) -Name $name
    Add-HierarchyChildren -Children $mg.properties.children -ParentId ([string]$mg.id)
}

if ($ScopeDepth -eq 'ResourceGroups') {
    foreach ($sub in @($script:Nodes.Values | Where-Object Kind -eq 'Subscription')) {
        try {
            $groups = @(Get-ArmItems -Path ("$($sub.ScopeId)/resourceGroups?api-version=2021-04-01"))
            foreach ($rg in $groups) { Add-Node -Id ([string]$rg.id) -Name ([string]$rg.name) -ParentId $sub.ScopeId }
        }
        catch { Append-Failure -Scope $sub.ScopeId -Operation 'DiscoverResourceGroups' -Message $_.Exception.Message }
    }
}

$orderedScopes = @($script:Nodes.Values | Sort-Object @{Expression={switch ($_.Kind) { 'ManagementGroup'{0}; 'Subscription'{1}; 'ResourceGroup'{2}; default{3}}}}, ScopeId)
Write-Host "Discovered $($orderedScopes.Count) scopes. Scanning PIM eligibility and active schedules." -ForegroundColor Cyan
# Journal per-scope records immediately, so an interrupted scan retains its evidence.
$eligiblePartial = Join-Path $dest 'pim_eligible_assignments.partial.csv'
$activePartial = Join-Path $dest 'pim_active_schedule_instances.partial.csv'
$rbacPartial = Join-Path $dest 'rbac_current_assignments.partial.csv'
$statusPartial = Join-Path $dest 'scan_status.partial.csv'
function Append-Checkpoint {
    param([object[]]$Items, [string]$Path)
    if (-not $Items -or $Items.Count -eq 0) { return }
    for ($attempt=1; $attempt -le 4; $attempt++) {
        try {
            $Items | Export-Csv -LiteralPath $Path -NoTypeInformation -Append -Encoding utf8 -ErrorAction Stop
            return
        }
        catch {
            if ($attempt -lt 4 -and $_.Exception.Message -match '(?i)being used by another process|file.*locked|sharing violation') {
                Start-Sleep -Milliseconds (200 * $attempt)
                continue
            }
            Append-Failure -Scope $Path -Operation 'Checkpoint' -Message $_.Exception.Message
            return
        }
    }
}
foreach ($node in $orderedScopes) {
    $eligibleBefore = $script:Eligible.Count
    $activeBefore = $script:Active.Count
    $rbacBefore = $script:Rbac.Count
    $stat = [ordered]@{ ScopeId=$node.ScopeId; ScopeKind=$node.Kind; ScopeName=$node.ScopeName; Eligible='Not requested'; ActiveSchedule='Not requested'; CurrentRbac='Not requested'; EligibleApiReturned=0; ActiveApiReturned=0; RbacApiReturned=0; DirectEligible=0; DirectActive=0; DirectRbac=0 }
    $base = "$($node.ScopeId)/providers/Microsoft.Authorization"
    try {
        $rows = @(Get-ArmItems -Path ($base + '/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=atScope()'))
        $stat.EligibleApiReturned = $rows.Count
        $stat.DirectEligible = Add-ScheduleRows -QueryScope $node.ScopeId -Category 'Eligible' -Items $rows
        $stat.Eligible = 'OK'
    }
    catch { $stat.Eligible = 'FAILED'; Append-Failure -Scope $node.ScopeId -Operation 'ListEligibility' -Message $_.Exception.Message }
    try {
        $rows = @(Get-ArmItems -Path ($base + '/roleAssignmentScheduleInstances?api-version=2020-10-01&$filter=atScope()'))
        $stat.ActiveApiReturned = $rows.Count
        $stat.DirectActive = Add-ScheduleRows -QueryScope $node.ScopeId -Category 'ActiveSchedule' -Items $rows
        $stat.ActiveSchedule = 'OK'
    }
    catch { $stat.ActiveSchedule = 'FAILED'; Append-Failure -Scope $node.ScopeId -Operation 'ListActiveSchedule' -Message $_.Exception.Message }
    if ($IncludeCurrentRbac) {
        try {
            $rows = @(Get-ArmItems -Path ($base + '/roleAssignments?api-version=2022-04-01&$filter=atScope()'))
            $stat.RbacApiReturned = $rows.Count
            $stat.DirectRbac = Add-DirectRbacRows -QueryScope $node.ScopeId -Items $rows
            $stat.CurrentRbac = 'OK'
        }
        catch { $stat.CurrentRbac = 'FAILED'; Append-Failure -Scope $node.ScopeId -Operation 'ListRbac' -Message $_.Exception.Message }
    }
    [void]$script:ScopesStatus.Add([pscustomobject]$stat)
    if ($script:Eligible.Count -gt $eligibleBefore) {
        Append-Checkpoint -Items @($script:Eligible.GetRange($eligibleBefore,$script:Eligible.Count-$eligibleBefore).ToArray()) -Path $eligiblePartial
    }
    if ($script:Active.Count -gt $activeBefore) {
        Append-Checkpoint -Items @($script:Active.GetRange($activeBefore,$script:Active.Count-$activeBefore).ToArray()) -Path $activePartial
    }
    if ($script:Rbac.Count -gt $rbacBefore) {
        Append-Checkpoint -Items @($script:Rbac.GetRange($rbacBefore,$script:Rbac.Count-$rbacBefore).ToArray()) -Path $rbacPartial
    }
    Append-Checkpoint -Items @([pscustomobject]$stat) -Path $statusPartial
    Write-Host ("{0}: eligible {1} ({2}); active schedules {3} ({4})" -f $node.ScopeName,$stat.DirectEligible,$stat.Eligible,$stat.DirectActive,$stat.ActiveSchedule)
}

} else {
    # Rehydrate the exact data already collected. No Az commands or ARM requests.
    # In particular, do not recalculate dates or mistake a missing file for zero grants.
    function Read-SavedEvidence {
        param([Parameter(Mandatory)][string]$Name, [switch]$AllowEmpty)
        $file = Join-Path $dest $Name
        if (Test-Path -LiteralPath $file -PathType Leaf) {
            return @(Import-Csv -LiteralPath $file)
        }
        $sentinel = $file + '.empty.txt'
        if ($AllowEmpty -and (Test-Path -LiteralPath $sentinel -PathType Leaf)) {
            return @()
        }
        throw "Missing required completed scan export: $file. The partial CSVs are recovery files and are not automatically treated as completed evidence."
    }

    $savedNodes = @(Read-SavedEvidence 'observed_scope_hierarchy.csv')
    $savedStatus = @(Read-SavedEvidence 'scan_status.csv')
    $savedEligible = @(Read-SavedEvidence 'pim_eligible_assignments.csv' -AllowEmpty)
    $savedActive = @(Read-SavedEvidence 'pim_active_schedule_instances.csv' -AllowEmpty)
    if ($savedNodes.Count -eq 0 -or $savedStatus.Count -eq 0) {
        throw 'The saved hierarchy or scan status CSV contains no rows. Report generation cannot assert scan coverage.'
    }
    foreach ($node in $savedNodes) {
        Add-Node -Id ([string]$node.ScopeId) -Name ([string]$node.ScopeName) -ParentId ([string]$node.ParentId)
    }
    foreach ($entry in $savedStatus) { [void]$script:ScopesStatus.Add($entry) }
    foreach ($entry in $savedEligible) { [void]$script:Eligible.Add($entry) }
    foreach ($entry in $savedActive) { [void]$script:Active.Add($entry) }

    if ($IncludeCurrentRbac) {
        foreach ($entry in @(Read-SavedEvidence 'rbac_current_assignments.csv' -AllowEmpty)) {
            [void]$script:Rbac.Add($entry)
        }
    }
    $errorFile = Join-Path $dest 'errors.csv'
    if (Test-Path -LiteralPath $errorFile -PathType Leaf) {
        foreach ($entry in @(Import-Csv -LiteralPath $errorFile)) { [void]$script:Failures.Add($entry) }
    }
    # Cross-check the completed evidence against scan_status before presenting counts.
    $expectedEligible = 0L
    $expectedActive = 0L
    foreach ($s in $savedStatus) {
        $expectedEligible += [long]$s.DirectEligible
        $expectedActive += [long]$s.DirectActive
    }
    if ($expectedEligible -ne $savedEligible.Count -or $expectedActive -ne $savedActive.Count) {
        throw "Saved evidence count mismatch. scan_status.csv reports eligible=$expectedEligible and active=$expectedActive, but completed CSVs contain eligible=$($savedEligible.Count) and active=$($savedActive.Count). Inspect exports before relying on the report."
    }
    $statusFile = Get-Item -LiteralPath (Join-Path $dest 'scan_status.csv')
    $asOf = $statusFile.LastWriteTimeUtc
    $roots = @($script:Nodes.Values | Where-Object { -not $_.ParentId } | Sort-Object ScopeName | ForEach-Object ScopeName)
    if ($roots.Count) { $startLabel = ($roots -join ', ') }
    $orderedScopes = @($script:Nodes.Values | Sort-Object Kind,ScopeId)
    Write-Host "Offline report mode: $($savedEligible.Count) eligibility records, $($savedActive.Count) active schedule records, $($orderedScopes.Count) scopes." -ForegroundColor Cyan
    Write-Host 'No Azure connection or Graph permissions required; all scan CSVs remain unchanged.' -ForegroundColor Cyan
}

# Join an existing PIM policy CSV ONLY to actual collected grants at an exact scope + role.
# This avoids labelling policy configurations for unused roles as actual eligibility.
$policyIndex = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$targets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($a in @($script:Eligible.ToArray()) + @($script:Active.ToArray())) {
    [void]$targets.Add("$($a.AssignmentScope)|$($a.RoleGuid)")
}
if ($PolicySettingsCsv) {
    $policyPath = (Resolve-Path -LiteralPath $PolicySettingsCsv -ErrorAction Stop).Path
    Import-Csv -LiteralPath $policyPath | ForEach-Object {
        $key = "$(Normalise-Scope ([string]$_.ScopeId))|$([string]$_.RoleGuid)"
        if ($targets.Contains($key) -and -not $policyIndex.ContainsKey($key)) {
            [void]$policyIndex.Add($key, [pscustomobject]@{
                PolicyId=[string]$_.PolicyId; MFA=[string]$_.ActivationMFA
                Context=[string]$_.CAContextEnabled; ContextId=[string]$_.CAContextId
                Approval=[string]$_.ApprovalRequired; Justification=[string]$_.JustificationRequired
                MaxDuration=[string]$_.ActivationMaxDuration
            })
        }
    }
}
function Find-Policy { param($A)
    $key = "$($A.AssignmentScope)|$($A.RoleGuid)"
    if ($policyIndex.ContainsKey($key)) { return $policyIndex[$key] }
    return $null
}

if (-not $ReportOnly) {
$eligiblePath = Join-Path $dest 'pim_eligible_assignments.csv'
$activePath = Join-Path $dest 'pim_active_schedule_instances.csv'
$rbacPath = Join-Path $dest 'rbac_current_assignments.csv'
$statusPath = Join-Path $dest 'scan_status.csv'
$scopePath = Join-Path $dest 'observed_scope_hierarchy.csv'
Export-Evidence -Rows @($script:Eligible.ToArray()) -File $eligiblePath
Export-Evidence -Rows @($script:Active.ToArray()) -File $activePath
if ($IncludeCurrentRbac) { Export-Evidence -Rows @($script:Rbac.ToArray()) -File $rbacPath }
$script:ScopesStatus.ToArray() | Export-Csv -LiteralPath $statusPath -NoTypeInformation -Encoding utf8
@($script:Nodes.Values | Sort-Object Kind,ScopeId) | Export-Csv -LiteralPath $scopePath -NoTypeInformation -Encoding utf8
if ($script:Failures.Count) { $script:Failures.ToArray() | Export-Csv -LiteralPath (Join-Path $dest 'errors.csv') -NoTypeInformation -Encoding utf8 }

}

# Create a main page usable by teams without RBAC/PIM knowledge and detailed evidence appendix.
$md = [System.Collections.Generic.List[string]]::new()
$detail = [System.Collections.Generic.List[string]]::new()
function Main { param([string]$Line) [void]$md.Add($Line) }
function Detail { param([string]$Line) [void]$detail.Add($Line) }
$coverageFailures = @($script:ScopesStatus | Where-Object { $_.Eligible -ne 'OK' -or $_.ActiveSchedule -ne 'OK' })
$discoveryFailures = @($script:Failures | Where-Object Operation -eq 'DiscoverResourceGroups')
$currentEligible = @($script:Eligible | Where-Object Status -eq 'Current')
$highBroad = @($currentEligible | Where-Object { $_.Tier -in @('Critical','Elevated') -and $_.ScopeKind -in @('ManagementGroup','Subscription') } | Sort-Object Tier, ScopeKind, Role, AssignmentScope)
$uncategorised = @($currentEligible | Where-Object Tier -eq 'Unclassified')
$eligibleCritical = @($currentEligible | Where-Object Tier -eq 'Critical')
$mgEligible = @($currentEligible | Where-Object ScopeKind -eq 'ManagementGroup')
$allNodeSub = @($script:Nodes.Values | Where-Object Kind -eq 'Subscription').Count
$allNodeRg = @($script:Nodes.Values | Where-Object Kind -eq 'ResourceGroup').Count
Main '# Azure resource privileged access: assignment scope and reach'
Main ''
Main "**$($timingLabel):** $($asOf.ToString('yyyy-MM-dd HH:mm')) | **Tenant:** $(ConvertTo-MarkdownCell $ctx.Tenant.Id) | **Observed starting scope:** $(ConvertTo-MarkdownCell $startLabel)"
Main ''
Main '**Status:** Preliminary access-governance review. Candidate scope exceptions are NOT confirmed violations of an approved standard. No Azure or Entra permissions were modified.'
Main ''
Main '## Executive summary'
Main ''
Main "- **$(($currentEligible).Count)** currently effective Azure resource PIM eligibility schedule instances collected, across **$($orderedScopes.Count)** observed scopes. An eligibility is a grant that can potentially be activated, not an active user session."
Main "- **$($eligibleCritical.Count)** current eligibilities in three critical built-in roles (Owner, User Access Administrator, RBAC Administrator); **$($mgEligible.Count)** eligible grants were directly assigned at management groups."
Main "- **$($highBroad.Count)** current Critical or Elevated eligibilities were assigned at management group or subscription scope. Each needs proportional business review, not automatic removal."
Main "- **$($uncategorised.Count)** current eligibilities have an unclassified role definition requiring separate privilege assessment."
Main "- **$($coverageFailures.Count)** discovered scopes had unsuccessful eligibility or active-schedule retrieval; **$($discoveryFailures.Count)** subscription resource-group discoveries failed. Coverage beyond the starting scope and at deeper levels is not assured."
Main ''
Main '## How to read this'
Main ''
Main 'Azure RBAC determines **what** a principal can do and **where**. A role assigned at a management group potentially applies to its descendants. PIM eligibility determines **who can activate** a role. PIM activation policies determine **the conditions for activation**. These are distinct forms of evidence.'
Main ''
Main '| Assignment scope | Potential reach | Scope review principle |'
Main '|---|---|---|'
Main '| Management group | All its descendant subscriptions and resources | Broad: justify critical or administrative privileges |'
Main '| Subscription | All its resource groups and resources | Broad for high privilege: validate operational need |'
Main '| Resource group | The group and its resources | Narrower; still sensitive for Owner and administrative roles |'
Main '| Individual resource | That resource and child resources | Often the narrowest assignable scope |'
Main ''
Main '## Coverage and evidence limitations'
Main ''
Main "- Hierarchy discovery found **$allNodeSub subscriptions** and **$allNodeRg resource groups**. A subscription-only run cannot establish whether resource-group or resource-level eligibilities exist."
Main '- The descendant-subscription numbers below reflect **observed nodes**, not a certified complete inventory of the tenant.'
Main '- A successful empty API result is not the same as an API failure. Any failed scopes are listed in `scan_status.csv` and `errors.csv`.'
Main '- Group principal memberships, indirect PIM for Groups eligibility and Entra directory-role PIM are not expanded. Custom-role privileges need their own review.'
if ($ReportOnly) { Main '- **Offline regeneration:** The displayed timestamp is the saved status CSV modification time, not a verified Azure collection timestamp. Only the Markdown files were regenerated.' }
Main '- Current eligibility instances are point-in-time evidence; they are not an activation history. Schedule status and time validity are retained, and pending records are not counted as current. PIM role policies do not inherit in the same way as RBAC grants.'
Main ''
Main '## Current PIM eligibility by sensitivity and direct assignment scope'
Main ''
Main '| Privilege tier | Management group | Subscription | Resource group | Resource / other | Total |'
Main '|---|---:|---:|---:|---:|---:|'
foreach ($tier in @('Critical','Elevated','Lower','Unclassified')) {
    $set = @($currentEligible | Where-Object Tier -eq $tier)
    $m = @($set | Where-Object ScopeKind -eq 'ManagementGroup').Count
    $s = @($set | Where-Object ScopeKind -eq 'Subscription').Count
    $r = @($set | Where-Object ScopeKind -eq 'ResourceGroup').Count
    $o = $set.Count - $m - $s - $r
    Main "| $tier | $m | $s | $r | $o | $($set.Count) |"
}
Main ''
Main '**Tier definitions:** Critical is limited to three recognised Azure RBAC administrator roles. Elevated includes Contributor and recognised built-in administrator-style roles. Custom roles and role definitions that could not be resolved are Unclassified, not assumed safe. This is a screening aid, not a comprehensive analysis of Actions, NotActions or DataActions.'
Main ''
Main '### Eligible grants by Azure role and assignment level'
Main ''
Main '| Azure role | Management group | Subscription | Resource group | Total current |'
Main '|---|---:|---:|---:|---:|'
foreach ($roleGroup in @($currentEligible | Group-Object Role | Sort-Object Count -Descending | Select-Object -First 20)) {
    $records = @($roleGroup.Group)
    $mgCount = @($records | Where-Object ScopeKind -eq 'ManagementGroup').Count
    $subCount = @($records | Where-Object ScopeKind -eq 'Subscription').Count
    $rgCount = @($records | Where-Object ScopeKind -eq 'ResourceGroup').Count
    Main "| $(ConvertTo-MarkdownCell $roleGroup.Name) | $mgCount | $subCount | $rgCount | $($records.Count) |"
}
Main ''
Main 'The table lists the 20 most frequent roles if more than 20 were collected; the evidence register retains every record. Resource-level assignments are outside this scan.'
Main ''
Main '## Scope hierarchy (directly granted eligibilities)'
Main ''
Main 'This map shows where the eligible grant originates, not duplicated grants inherited by a child. Granting a role at a parent scope can give access to child scopes once activated.'
Main ''
Main '```text'
function Emit-ScopeTree { param([string]$NodeId,[int]$Level)
    $n = $script:Nodes[$NodeId]
    $direct = @($currentEligible | Where-Object AssignmentScope -eq $NodeId)
    $critical = @($direct | Where-Object Tier -eq 'Critical').Count
    $childRg = @($script:Nodes.Values | Where-Object { $_.ParentId -ieq $NodeId -and $_.Kind -eq 'ResourceGroup' }).Count
    $rgSuffix = if ($childRg -gt 0) { "; observed RGs=$childRg" } else { '' }
    Main ((('  ' * $Level) + '{0}: {1} [eligible={2}; critical={3}{4}]') -f $n.Kind,$n.ScopeName,$direct.Count,$critical,$rgSuffix)
    foreach ($child in @($script:Nodes.Values | Where-Object { $_.ParentId -ieq $NodeId -and $_.Kind -in @('ManagementGroup','Subscription') } | Sort-Object ScopeName)) {
        Emit-ScopeTree -NodeId $child.ScopeId -Level ($Level + 1)
    }
}
foreach ($treeRoot in @($script:Nodes.Values | Where-Object { -not $_.ParentId } | Sort-Object ScopeName)) {
    Emit-ScopeTree -NodeId $treeRoot.ScopeId -Level 0
}
Main '```'
Main ''
Main 'Individual resource groups are intentionally summarised, rather than drawn as hundreds of branches. Their direct eligible assignments appear in the technical evidence register when `-ScopeDepth ResourceGroups` is selected.'
Main ''
Main '## Scope review candidates with primary evidence'
Main ''
if ($highBroad.Count -eq 0) { Main 'No current Critical/Elevated eligibility was collected directly at management group or subscription scope. This does not exclude deeper scopes or scopes with failed retrieval.' }
else {
    Main "Showing up to $Examples cases. The evidence appendix includes all collected eligibilities."
    Main ''
    Main '| Role and tier | Principal ID / type | Direct assignment scope | Observed child subscriptions | Valid until | Policy activation control | Exact evidence reference |'
    Main '|---|---|---|---:|---|---|---|'
    foreach ($e in @($highBroad | Select-Object -First $Examples)) {
        $p = Find-Policy $e
        $policyText = 'Not joined'
        if ($p) { $policyText = "MFA=$(ConvertTo-MarkdownCell $p.MFA); context=$(ConvertTo-MarkdownCell $p.Context); approval=$(ConvertTo-MarkdownCell $p.Approval)" }
        Main "| $(ConvertTo-MarkdownCell $e.Role) ($($e.Tier)) | $(ConvertTo-MarkdownCell $e.PrincipalId) ($(ConvertTo-MarkdownCell $e.PrincipalType)) | $(ConvertTo-MarkdownCell $e.ScopePath) | $($e.ObservedChildSubscriptions) | $(ConvertTo-MarkdownCell $e.EndDateTime) | $policyText | $(ConvertTo-MarkdownCell $e.ScheduleId) |"
    }
}
Main ''
Main '### Decisions needed'
Main ''
Main '1. **Access owners:** For each broad Critical/Elevated eligibility, document why the role needs that assignment scope. Consider more specific resource groups, resources or separate narrowly scoped roles where feasible.'
Main '2. **Identity governance:** Confirm whether each eligible user/group still needs access, whether the eligibility is time-bound and whether group membership changes who can activate it.'
Main '3. **PIM control owners:** Where a matching policy row is available, validate MFA or authentication-context protection, approval and activation duration. Do not infer Conditional Access sign-in protection from the PIM policy alone.'
Main '4. **RBAC platform owners:** Review any current RBAC grants separately. Service principals cannot perform interactive PIM role activation; their assigned privileges require workload-identity least-privilege controls.'
Main '5. **Security governance:** Agree the permitted scope by role family and record exceptions; without an approved baseline, the broad-scope cases are candidates for review, not definite non-compliance.'
Main ''
Main '### Evidence required to close each scope review'
Main ''
Main 'A reviewed record must include the **schedule ID**, **principal**, **role definition ID**, **exact assignment scope**, **observed inherited reach**, **business justification**, **approved target scope** and an Azure re-query showing the approved state or documented exception.'
Main ''
Main '## Separate active-access observations'
Main ''
Main "PIM active schedule instances collected: **$($script:Active.Count)**. Those with `AssignmentType=Activated` can be distinguished in `pim_active_schedule_instances.csv` from `Assigned` entries."
if ($IncludeCurrentRbac) { Main "Ordinary RBAC role assignments collected: **$($script:Rbac.Count)**. This is a separate evidence stream and may overlap active schedules; counts must not be added together." }
else { Main 'Ordinary RBAC evidence was not included. If `rbac_current_assignments.csv` exists in the output directory, run this generator with `-ReportOnly -IncludeCurrentRbac`. Otherwise, a separate RBAC collection would be needed.' }
Main ''
Main '## Primary sources and audit trail'
Main ''
Main '- `pim_eligible_assignments.csv`: individual eligibility schedule instance IDs, principal, role, exact scope, API lifecycle status and validity dates.'
Main '- `pim_active_schedule_instances.csv`: active schedule instances, assignment type and linked eligibility identifiers.'
if ($IncludeCurrentRbac) { Main '- `rbac_current_assignments.csv`: separately enumerated active role assignments and assignment IDs.' }
Main '- `observed_scope_hierarchy.csv`: nodes actually discovered in the accessible hierarchy.'
Main '- `scan_status.csv` and `errors.csv` (if present): successful, failed and unverified collection.'
if ($PolicySettingsCsv) { Main '- Supplied `policy_settings.csv`: per-role PIM policy controls joined ONLY on exact role GUID and scope. A policy alone does not establish eligibility.' }
Main ''
Main '- Microsoft ARM eligibility schedule API: https://learn.microsoft.com/en-us/rest/api/authorization/role-eligibility-schedule-instances/list-for-scope?view=rest-authorization-2020-10-01'
Main '- Microsoft RBAC scope best practice: https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices'

Detail '# Azure PIM assignment scope: technical evidence register'
Detail ''
Detail "**$($timingLabel):** $($asOf.ToString('yyyy-MM-dd HH:mm')) | **Entries:** $($script:Eligible.Count) eligibility schedule instances."
Detail ''
Detail 'Rows identify independent grants, not duplicated role-policy settings. Grant scope is the source scope, while child subscriptions show observed reach.'
Detail ''
Detail '| State | Role | Tier | Principal ID / type | Grant scope and hierarchy | Descendant subscriptions (observed) | Start / expiry | Schedule instance ID | Role definition ID | PIM MFA / authentication context / approval | Policy ID |'
Detail '|---|---|---|---|---|---:|---|---|---|---|---|'
foreach ($e in @($script:Eligible | Sort-Object Tier, ScopeKind, Role, AssignmentScope, PrincipalId)) {
    $p = Find-Policy $e
    $desc = if($p){"MFA=$($p.MFA); CA=$($p.Context); approval=$($p.Approval)"}else{'Not joined'}
    $pid = if($p){$p.PolicyId}else{''}
    Detail "| $(ConvertTo-MarkdownCell $e.Status) | $(ConvertTo-MarkdownCell $e.Role) | $(ConvertTo-MarkdownCell $e.Tier) | $(ConvertTo-MarkdownCell "$($e.PrincipalId) ($($e.PrincipalType))") | $(ConvertTo-MarkdownCell $e.ScopePath) ; $(ConvertTo-MarkdownCell $e.AssignmentScope) | $($e.ObservedChildSubscriptions) | $(ConvertTo-MarkdownCell "start=$($e.StartDateTime), end=$($e.EndDateTime)") | $(ConvertTo-MarkdownCell $e.ScheduleId) | $(ConvertTo-MarkdownCell $e.RoleDefinitionId) | $(ConvertTo-MarkdownCell $desc) | $(ConvertTo-MarkdownCell $pid) |"
}
Detail ''
Detail '## Active schedule instance evidence (not proof of eligibility)'
Detail ''
Detail '| AssignmentType | Role | Principal ID | Exact assigned scope | Start | End | Schedule ID | Origin role-assignment ID |'
Detail '|---|---|---|---|---|---|---|---|'
foreach ($a in @($script:Active | Sort-Object Role, AssignmentScope, PrincipalId)) {
    Detail "| $(ConvertTo-MarkdownCell $a.AssignmentType) | $(ConvertTo-MarkdownCell $a.Role) | $(ConvertTo-MarkdownCell $a.PrincipalId) | $(ConvertTo-MarkdownCell $a.AssignmentScope) | $(ConvertTo-MarkdownCell $a.StartDateTime) | $(ConvertTo-MarkdownCell $a.EndDateTime) | $(ConvertTo-MarkdownCell $a.ScheduleId) | $(ConvertTo-MarkdownCell $a.OriginRoleAssignmentId) |"
}
if ($IncludeCurrentRbac) {
    Detail ''
    Detail '## Ordinary Azure RBAC grants (independent evidence stream)'
    Detail ''
    Detail '| Role | Principal ID / type | Exact scope | Observed child subscriptions | Role assignment ID | Conditional assignment expression |'
    Detail '|---|---|---|---:|---|---|'
    foreach ($a in @($script:Rbac | Sort-Object Role, AssignmentScope, PrincipalId)) {
        Detail "| $(ConvertTo-MarkdownCell $a.Role) | $(ConvertTo-MarkdownCell "$($a.PrincipalId) ($($a.PrincipalType))") | $(ConvertTo-MarkdownCell $a.AssignmentScope) | $($a.ObservedChildSubscriptions) | $(ConvertTo-MarkdownCell $a.RoleAssignmentId) | $(ConvertTo-MarkdownCell $a.Condition) |"
    }
}
Detail ''
Detail '## Scopes with collection errors'
Detail ''
Detail '| Scope | Eligible query | Active schedule query | Direct RBAC query |'
Detail '|---|---|---|---|'
foreach ($s in @($script:ScopesStatus | Where-Object { $_.Eligible -ne 'OK' -or $_.ActiveSchedule -ne 'OK' -or ($IncludeCurrentRbac -and $_.CurrentRbac -ne 'OK') })) {
    Detail "| $(ConvertTo-MarkdownCell $s.ScopeId) | $(ConvertTo-MarkdownCell $s.Eligible) | $(ConvertTo-MarkdownCell $s.ActiveSchedule) | $(ConvertTo-MarkdownCell $s.CurrentRbac) |"
}
Detail ''
Detail '**Collection limitations:** No Graph permission is requested. Group membership and PIM for Groups are excluded. Descendants are limited to the observed hierarchy. Individual-resource assignments and resource groups omitted by the selected scan depth are not audited.'

$mainPath = Join-Path $dest 'Azure-PIM-Assignment-Scope-Review.md'
$appendixPath = Join-Path $dest 'Azure-PIM-Assignment-Evidence-Register.md'
$md.ToArray() | Set-Content -LiteralPath $mainPath -Encoding utf8
$detail.ToArray() | Set-Content -LiteralPath $appendixPath -Encoding utf8
Write-Host "`nConfluence report: $mainPath" -ForegroundColor Green
Write-Host "Evidence appendix: $appendixPath" -ForegroundColor Green
if ($ReportOnly) { Write-Host 'Report-only complete. The original CSV evidence was not modified.' -ForegroundColor Cyan }
Write-Host "Eligibility $($script:Eligible.Count), active schedules $($script:Active.Count), RBAC $($script:Rbac.Count), scan errors $($script:Failures.Count)" -ForegroundColor Cyan
