## Where to run these queries (and why Resource Explorer fails)

* **Azure Resource Explorer** (resources.azure.com and the Portal “Resource Explorer”) is a REST object browser for ARM. It does not execute KQL. That’s why `let` errors out. ([Microsoft Azure][1])

Run KQL in one of these instead:

1. **Azure Resource Graph Explorer** in the Azure Portal
   Portal search: “Resource Graph Explorer” → open → top bar “Select scope” → pick your management group → paste query → Run. ([Microsoft Learn][3])

2. **Azure CLI**

   ```bash
   az graph query --management-groups <mgId> --graph-query "<KQL>"
   ```

   Requires the resource‑graph extension. ([Microsoft Learn][6])

3. **PowerShell**

   ````powershell
   Search-AzGraph -ManagementGroup <mgId> -Query "<KQL>"
   ``` :contentReference[oaicite:9]{index=9}

   ````

4. **Azure Monitor Logs (Log Analytics)** with cross‑service **`arg("")`**
   Open Azure Monitor → Logs → pick a workspace → run KQL that calls `arg("").Resources` or `arg("").PolicyResources`. You can use `let` here, and even join ARG data with logs. Caveats: preview, `arg()` returns the first \~1,000 records, and the editor may flag valid ARG syntax as an “error” while still running. ([Microsoft Learn][4])

---

## Copy‑paste queries you can run now

### A) Pure Resource Graph Explorer or CLI/PowerShell (no `let`)

**1) Expected storage accounts by tag value list**
Replace the values in the dynamic array.

```kusto
resources
| where type =~ "Microsoft.Storage/storageAccounts"
| extend tagKeys = bag_keys(tags)
| mv-expand tagKeys to typeof(string)
| where tagKeys =~ "myTag"
| extend tagVal = tostring(tags[tagKeys])
| where tagVal in~ (dynamic(["VALUE1","VALUE2"]))   // edit your allowed values
| project id, name, resourceGroup, subscriptionId, tagVal
```

ARG tag and type examples follow this pattern. ([Microsoft Learn][3])

**2) Latest policy evaluation for your assignment**

```kusto
policyresources
| where type =~ 'Microsoft.PolicyInsights/policystates'
| where name == 'latest'
| extend assignmentId = tolower(tostring(properties['policyAssignmentId']))
| where assignmentId endswith tolower('/policyAssignments/Your-Assignment-Name')   // edit
| project resourceId = tostring(properties['resourceId']),
          complianceState = tostring(properties['complianceState'])
```

`PolicyResources` is the correct table for policy states in ARG. ([Microsoft Learn][2])

**3) The gap: should match by tag, but not seen by the assignment**

```kusto
Resources
| where type =~ "Microsoft.Storage/storageAccounts"
| extend tagKeys = bag_keys(tags)
| mv-expand tagKeys to typeof(string)
| where tagKeys =~ "myTag"
| extend tagVal = tostring(tags[tagKeys])
| where tagVal in~ (dynamic(["VALUE1","VALUE2"]))   // edit
| project id, name, resourceGroup, subscriptionId, tagVal
| join kind=leftanti (
    policyresources
    | where type =~ 'Microsoft.PolicyInsights/PolicyStates'
    | where properties.policyAssignmentName == "Your-Assignment-Name"   // edit
    | summarize arg_max(properties.timestamp, *) by resourceId = tostring(properties.resourceId)
    | project resourceId
  ) on $left.id == $right.resourceId
| project id, name, resourceGroup, tagVal
```

**4) One query that classifies each storage account**

```kusto
resources
| where type =~ "Microsoft.Storage/storageAccounts"
| extend tagKeys = bag_keys(tags)
| mv-expand tagKeys to typeof(string)
| where tagKeys =~ "myTag"
| extend tagVal = tostring(tags[tagKeys])
| summarize any(tagVal) by id, name, resourceGroup, subscriptionId
| extend expectedToMatch = iif(isempty(tagVal), "NoTag",
                          iif(tagVal in~ (dynamic(["VALUE1","VALUE2"])), "Expected", "NotExpected"))
| join kind=leftouter (
    policyresources
    | where type =~ 'Microsoft.PolicyInsights/PolicyStates'
    | where properties.policyAssignmentName == "Your-Assignment-Name"
    | summarize arg_max(properties.timestamp, *) by resourceId = tostring(properties.resourceId)
    | project resourceId, complianceState = tostring(properties.complianceState)
  ) on $left.id == $right.resourceId
| extend evalSeen = iif(isnull(complianceState), "NotEvaluated", "Evaluated")
| project name, resourceGroup, subscriptionId, tagVal, expectedToMatch, evalSeen, complianceState
```

> Tip: use `=~`/`in~` for case‑insensitive matches to mimic Policy behaviour. ([Microsoft Learn][3])

### B) Azure Monitor Logs route with `let` (full KQL comfort)

Open Azure Monitor → Logs → your workspace → run:

```kusto
let allowed = dynamic(["VALUE1","VALUE2"]);
let tagName = "myTag";
let assignmentName = "Your-Assignment-Name";

let expected =
    arg("").Resources
    | where type =~ "Microsoft.Storage/storageAccounts"
    | extend tagKeys = bag_keys(tags)
    | mv-expand tagKeys to typeof(string)
    | where tagKeys =~ tagName
    | extend tagVal = tostring(tags[tagKeys])
    | where tagVal in~ (allowed)
    | project id, name, resourceGroup, subscriptionId, tagVal;

let evaluated =
    arg("").PolicyResources
    | where type =~ 'Microsoft.PolicyInsights/PolicyStates'
    | where properties.policyAssignmentName == assignmentName
    | summarize arg_max(properties.timestamp, *) by resourceId = tostring(properties.resourceId)
    | project resourceId, complianceState = tostring(properties.complianceState);

expected
| join kind=leftanti evaluated on $left.id == $right.resourceId
```

This uses the `arg("")` cross‑service connector. Expect the editor to show false‑positive squiggles and the `arg()` 1,000‑row cap. It still runs. ([Microsoft Learn][4])

---

## Why this works better than the Policy blade

* You get a deterministic “should match” set from the live resource inventory, then compare with what Policy actually evaluated.
* You see exactly which storage accounts never got a Policy state, which is your symptom.
* You can run it tenant‑wide at management group scope. ([Microsoft Learn][6])

---

## Trade offs

* **ARG Explorer**
  Fast, native, no agents. Subset of KQL and UX is spartan. If `let` gives you grief, stick to the no‑`let` versions above. ([Microsoft Learn][2])
* **Log Analytics with `arg()`**
  Full KQL including `let` and rich joins. Preview limitations: 1,000 rows from `arg()`, editor warnings that you can ignore, and slightly higher latency. ([Microsoft Learn][4])

---

## Next steps

1. Pick a route: ARG Explorer or Log Analytics.
2. Paste the “classify” query and replace `VALUE1/2` and the assignment name.
3. If you see “Expected + NotEvaluated” rows, the assignment scope, mode, or parameters aren’t catching those storage accounts. Fix the assignment, then re‑scan.
4. Re‑run until the Diff is empty.

If you want, drop your management group ID and assignment name here. I’ll hand you a ready‑to‑run command for CLI and PowerShell.

**Risks**

* Running at subscription scope by mistake hides cross‑sub results. Always set scope to the management group in the tool you use. ([Microsoft Learn][6])

**Final check**
Your instinct to start with `audit` is right. Keep it parameterised, get the Diff to zero, then consider `deny` later.

[1]: https://azure.microsoft.com/en-us/blog/azure-resource-explorer-a-new-tool-to-discover-the-azure-api/?utm_source=chatgpt.com "Azure Resource Explorer: a new tool to discover the ..."
[2]: https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language "Understand the query language - Azure Resource Graph | Microsoft Learn"
[3]: https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/starter?utm_source=chatgpt.com "Starter query samples - Azure Resource Graph"
[4]: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/azure-monitor-data-explorer-proxy "Correlate data in Azure Data Explorer and Azure Resource Graph with data in a Log Analytics workspace - Azure Monitor | Microsoft Learn"
[5]: https://learn.microsoft.com/en-us/cli/azure/graph?view=azure-cli-latest&utm_source=chatgpt.com "az graph"
[6]: https://learn.microsoft.com/en-us/azure/governance/resource-graph/first-query-azurecli?utm_source=chatgpt.com "Quickstart: Run Resource Graph query using Azure CLI"
