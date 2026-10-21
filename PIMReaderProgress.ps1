#requires -Version 7.0
<#
.SYNOPSIS
    Read a running Get-AzurePimPolicyTree-v4.ps1 scan's live journals.
.DESCRIPTION
    Read-only. Does not contact Azure or open the large partial.jsonl file.
    Opens CSVs with FileShare.ReadWrite to avoid interfering with the scan.
    Scope totals are limited to subscriptions whose list request has run.
.EXAMPLE
    ./Get-AzurePimScanStatus.ps1 -OutputDirectory ./AzurePimReport
.EXAMPLE
    ./Get-AzurePimScanStatus.ps1 -OutputDirectory "$env:TEMP/AzurePimReport" -Watch
#>
[CmdletBinding()]
param(
    [string] $OutputDirectory = (Join-Path (Get-Location).Path 'AzurePimReport'),
    [switch] $Watch,
    [ValidateRange(10, 3600)]
    [int] $IntervalSeconds = 60
)

$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $OutputDirectory -ErrorAction Stop).Path

function Read-LiveCsv {
    param([Parameter(Mandatory)] [string] $Path)
    if (-not [IO.File]::Exists($Path)) { return }
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true)
        try { $content = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    }
    finally { $stream.Dispose() }

    if ([string]::IsNullOrWhiteSpace($content)) { return }
    # An append may be in progress. Ignore an incomplete final line.
    if (-not $content.EndsWith("`n")) {
        $lastBreak = $content.LastIndexOf("`n")
        if ($lastBreak -lt 0) { return }
        $content = $content.Substring(0, $lastBreak + 1)
    }
    $content | ConvertFrom-Csv
}

function Get-ListingTotals {
    param([object[]] $Requests, [ValidateSet('resourceGroups','resources')] [string] $Leaf)
    $bySub = @{}
    $failed = @{}
    foreach ($request in $Requests) {
        if ($request.Path -match ("(?i)/subscriptions/([^/?]+)/" + $Leaf + "\?")) {
            $id = $Matches[1].ToLowerInvariant()
        }
        else { continue }
        if (-not $bySub.ContainsKey($id)) { $bySub[$id] = [long] 0 }
        if ($request.Result -eq 'OK') {
            [long] $number = 0
            if ([long]::TryParse([string] $request.ItemCount, [ref] $number)) {
                $bySub[$id] += $number
            }
        }
        else { $failed[$id] = $true }
    }
    [long] $sum = 0
    foreach ($value in $bySub.Values) { $sum += [long] $value }
    [pscustomobject] @{
        BySub = $bySub
        TotalKnown = $sum
        EnumeratedSubscriptions = $bySub.Count
        FailedSubscriptions = $failed.Count
    }
}

function Show-Status {
    param($PreviousSnapshot)
    $scopeFile = Get-ChildItem -LiteralPath $resolved -Filter 'AzurePim_*_scopes.live.csv' -File |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $scopeFile) { throw "No *_scopes.live.csv found in $resolved" }
    $stem = $scopeFile.FullName -replace '_scopes\.live\.csv$', ''
    $requestFile = "${stem}_requests.live.csv"
    $policyFile = "${stem}_policies.partial.jsonl"
    $scopes = @(Read-LiveCsv -Path $scopeFile.FullName)
    $requests = @(Read-LiveCsv -Path $requestFile)

    $subs = @($scopes | Where-Object ScopeKind -eq 'Subscription')
    $mgs = @($scopes | Where-Object ScopeKind -eq 'ManagementGroup')
    $rgScopes = @($scopes | Where-Object ScopeKind -eq 'ResourceGroup')
    $resourceScopes = @($scopes | Where-Object ScopeKind -eq 'Resource')
    $rgLists = Get-ListingTotals -Requests $requests -Leaf 'resourceGroups'
    $resourceLists = Get-ListingTotals -Requests $requests -Leaf 'resources'
    $rgRemainingKnown = [math]::Max(0, $rgLists.TotalKnown - $rgScopes.Count)
    $resourcesRemainingKnown = [math]::Max(0, $resourceLists.TotalKnown - $resourceScopes.Count)
    $policies = [IO.FileInfo] $policyFile
    $journalGB = if ($policies.Exists) { [math]::Round($policies.Length / 1GB, 2) } else { 0 }
    $now = Get-Date
    $ageSeconds = if ($policies.Exists) { [int]($now - $policies.LastWriteTime).TotalSeconds } else { $null }
    $lastScope = if ($scopes.Count) { $scopes[-1] } else { $null }
    $lastRequest = if ($requests.Count) { $requests[-1] } else { $null }
    $scopeAgeSeconds = [int]($now - (Get-Item -LiteralPath $scopeFile.FullName).LastWriteTime).TotalSeconds
    $errors = @($requests | Where-Object Result -eq 'FAILED').Count

    Write-Host "`nAzure PIM scan: $($now.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
    Write-Host "Run prefix: $(Split-Path $stem -Leaf)"
    Write-Host ('Completed management groups: {0} | subscriptions: {1}' -f $mgs.Count, $subs.Count)
    Write-Host ('Resource groups: {0} completed / {1} discovered in {2}/{3} subscriptions' -f $rgScopes.Count, $rgLists.TotalKnown, $rgLists.EnumeratedSubscriptions, $subs.Count)
    Write-Host ('   At least {0} discovered resource groups still to process. Counts for subscriptions not yet listed are UNKNOWN.' -f $rgRemainingKnown)
    if ($resourceLists.EnumeratedSubscriptions -or $resourceScopes.Count) {
        Write-Host ('Resources: {0} completed / {1} discovered in {2}/{3} subscriptions' -f $resourceScopes.Count, $resourceLists.TotalKnown, $resourceLists.EnumeratedSubscriptions, $subs.Count)
        Write-Host ('   At least {0} discovered resources still to process.' -f $resourcesRemainingKnown)
    }
    Write-Host ('Requests: {0} logged ({1} failed). Partial JSONL: {2:N2} GB, last written {3} seconds ago.' -f $requests.Count, $errors, $journalGB, $ageSeconds)
    if ($lastScope) {
        Write-Host ('Last completed scope ({0} seconds since scope journal update): {1} [{2}] ({3}); policies: {4}' -f $scopeAgeSeconds, $lastScope.ScopeId, $lastScope.ScopeKind, $lastScope.Status, $lastScope.PolicyRecords)
    }
    if ($lastRequest) {
        Write-Host ('Last logged ARM request [{0}]: {1}' -f $lastRequest.Result, $lastRequest.Path)
    }
    if ($rgLists.FailedSubscriptions -or $resourceLists.FailedSubscriptions) {
        Write-Warning 'Some scope-listing requests failed. Discovered totals may be incomplete.'
    }
    if ($PreviousSnapshot) {
        $elapsedMinutes = ($now - $PreviousSnapshot.When).TotalMinutes
        $completedThen = $PreviousSnapshot.CompletedDeepScopes
        $completedNow = $rgScopes.Count + $resourceScopes.Count
        if ($elapsedMinutes -gt 0) {
            $rate = ($completedNow - $completedThen) / $elapsedMinutes
            Write-Host ('Deep scopes completed since previous sample: {0}; rate: {1:N1}/minute' -f ($completedNow - $completedThen), $rate)
            if ($rate -gt 0 -and $rgLists.EnumeratedSubscriptions -eq $subs.Count -and $resourceLists.EnumeratedSubscriptions -eq 0 -and $subs.Count -gt 0) {
                Write-Host ('Approximate time for remaining DISCOVERED resource groups: {0:N0} minutes at this rate (excludes final report generation and any later resource scan)' -f ($rgRemainingKnown / $rate))
            }
        }
    }
    [pscustomobject] @{
        When = $now
        CompletedDeepScopes = $rgScopes.Count + $resourceScopes.Count
    }
}

$previous = $null
do {
    try { $previous = Show-Status -PreviousSnapshot $previous }
    catch { Write-Warning "Cannot read a consistent journal snapshot yet: $($_.Exception.Message)" }
    if ($Watch) { Start-Sleep -Seconds $IntervalSeconds }
} while ($Watch)
