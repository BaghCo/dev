#requires -Version 7.0
<#
.SYNOPSIS
    Export Microsoft Entra authentication-context definitions and Conditional
    Access policies as read-only JSON, for the Azure PIM Visual Review report.
.DESCRIPTION
    Uses Microsoft Graph. It does not change policies or Azure resources.
    Azure RBAC Reader alone does NOT authorise these Graph requests.
    An appropriate Entra directory role (for example Security Reader or Global
    Reader), an appropriate Graph delegated token and consent may be required.
    CA policy exports can reveal sensitive security configuration. Store securely.
.EXAMPLE
    ./Export-PimAuthenticationContextEvidence.ps1 -TenantId '00000000-0000-0000-0000-000000000000' -OutputDirectory './EntraEvidence'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string] $TenantId,
    [string] $OutputDirectory = (Join-Path (Get-Location).Path 'EntraEvidence')
)
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Connect-MgGraph -TenantId $TenantId -Scopes 'Policy.Read.All','AuthenticationContext.Read.All' -ContextScope Process -NoWelcome -ErrorAction Stop | Out-Null
$current = Get-MgContext
if (-not $current -or $current.TenantId -ne $TenantId) {
    throw 'Graph connection is not in the requested tenant; no files were exported.'
}

function Read-GraphCollection {
    param([Parameter(Mandatory)][string] $Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $pages = 0
    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $pages++
        if ($pages -gt 1000) { throw "Unexpectedly many pages for $Uri; aborting." }
        $body = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Json -ErrorAction Stop
        if ($body -is [string]) { $page = ConvertFrom-Json -InputObject $body -Depth 100 -ErrorAction Stop }
        else { $page = $body }
        if ($null -ne $page.value) {
            foreach ($item in @($page.value)) {
                if ($null -ne $item) { [void] $items.Add($item) }
            }
        }
        $next = [string] $page.'@odata.nextLink'
    }
    return $items.ToArray()
}

$root = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess'
Write-Host 'Reading Entra authentication-context definitions (Graph)...'
$contexts = @(Read-GraphCollection -Uri "$root/authenticationContextClassReferences")
Write-Host 'Reading Entra Conditional Access policies (Graph)...'
$policies = @(Read-GraphCollection -Uri "$root/policies")

[void](New-Item -ItemType Directory -Force -Path $OutputDirectory)
$directory = (Resolve-Path -LiteralPath $OutputDirectory).Path
# Use a Graph-like { value: [...] } envelope accepted by Azure-PIM-Visual-Review.html.
([pscustomobject]@{value=@($contexts)}) | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath (Join-Path $directory 'authenticationContexts.json') -Encoding utf8
([pscustomobject]@{value=@($policies)}) | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath (Join-Path $directory 'conditionalAccessPolicies.json') -Encoding utf8
Write-Host "Saved $($contexts.Count) authentication contexts and $($policies.Count) Conditional Access policies to $directory" -ForegroundColor Green
Write-Warning 'These JSON exports include security-sensitive policy details. Share only with authorised recipients.'
