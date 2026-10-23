$rows = @(Import-Csv '.\PIMScopeAudit\pim_eligible_assignments.csv')

$rows |
    Select-Object Role, ScopeName, PrincipalType,
        PrincipalId, MemberType, StartDateTime, EndDateTime |
    Format-Table -AutoSize

$rows |
    Group-Object PrincipalType |
    Select-Object Name, Count
