$active = Import-Csv '.\PIMScopeAudit\pim_active_schedule_instances.csv'

$active |
    Group-Object AssignmentType, MemberType |
    Select-Object Name, Count |
    Format-Table -AutoSize

$active |
    Where-Object {
        $_.AssignmentType -eq 'Assigned' -and
        $_.MemberType -eq 'Direct' -and
        [string]::IsNullOrWhiteSpace($_.EndDateTime)
    } |
    Select-Object Role, PrincipalType, PrincipalId,
        ScopeName, AssignmentScope, EndDateTime |
    Sort-Object Role, ScopeName |
    Format-Table -AutoSize

#check distribution
$active = Import-Csv '.\PIMScopeAudit\pim_active_schedule_instances.csv'

$active |
    Select-Object AssignmentType, MemberType,
        @{N='Expiry'; E={
            if ([string]::IsNullOrWhiteSpace($_.EndDateTime)) {
                'No end date'
            } else {
                'Time-bound'
            }
        }} |
    Group-Object AssignmentType, MemberType, Expiry |
    Sort-Object Count -Descending |
    Select-Object Name, Count |


# detail
 $standing = $active | Where-Object {
    $_.AssignmentType -eq 'Assigned' -and
    $_.MemberType -eq 'Direct' -and
    [string]::IsNullOrWhiteSpace($_.EndDateTime) -and
    $_.Role -in $privileged -and
    $_.ScopeKind -in @('ManagementGroup','Subscription')
}

$standing |
    Sort-Object ScopeKind, ScopeName, Role |
    Select-Object ScopeKind, ScopeName, Role,
        PrincipalType, PrincipalId,
        AssignmentScope, ScheduleId,
        Status, Condition |
    Export-Csv '.\PIMScopeAudit\Standing-Privileged-Access.csv' `
        -NoTypeInformation

Write-Host "Assignments exported: $($standing.Count)"
    Format-Table -AutoSize
    
# limit to privileged roles.
$privileged = @(
    'Owner'
    'User Access Administrator'
    'Role Based Access Control Administrator'
    'Contributor'
    'Key Vault Administrator'
)

$active |
    Where-Object {
        $_.AssignmentType -eq 'Assigned' -and
        $_.MemberType -eq 'Direct' -and
        [string]::IsNullOrWhiteSpace($_.EndDateTime) -and
        $_.Role -in $privileged -and
        $_.ScopeKind -in @('ManagementGroup','Subscription')
    } |
    Group-Object ScopeKind, Role |
    Sort-Object Count -Descending |
    Select-Object Name, Count |
    Format-Table -AutoSize

# detail
 $standing = $active | Where-Object {
    $_.AssignmentType -eq 'Assigned' -and
    $_.MemberType -eq 'Direct' -and
    [string]::IsNullOrWhiteSpace($_.EndDateTime) -and
    $_.Role -in $privileged -and
    $_.ScopeKind -in @('ManagementGroup','Subscription')
}

$standing |
    Sort-Object ScopeKind, ScopeName, Role |
    Select-Object ScopeKind, ScopeName, Role,
        PrincipalType, PrincipalId,
        AssignmentScope, ScheduleId,
        Status, Condition |
    Export-Csv '.\PIMScopeAudit\Standing-Privileged-Access.csv' `
        -NoTypeInformation

Write-Host "Assignments exported: $($standing.Count)"
