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
