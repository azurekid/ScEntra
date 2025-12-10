# ScEntra Maintenance & Troubleshooting Guide

<p align="center">
  <img src="images/ScEntra-background.png" alt="ScEntra" width="400" style="max-width: 100%; height: auto;">
</p>

This document explains how the module is structured, how data flows from Microsoft Graph into the visualization, and how to extend or debug the solution. Use it alongside `QUICKSTART.md` when maintaining the project as a community effort.

## Repository Layout Overview

| Path | Purpose |
| --- | --- |
| `Public/` | Exported cmdlets (`Connect-ScEntraGraph`, `Invoke-ScEntraAnalysis`, etc.). These files contain user-facing parameter sets and should remain thin wrappers over the private logic. |
| `Private/` | Implementation scripts for data acquisition, graph building, report rendering, anonymization, and helper utilities. |
| `Generate-ReportFromJson.ps1` | Converts a previously captured JSON payload into HTML using the latest template. |
| `Invoke-JsonAnonymizer.ps1` | Rewrites IDs, UPNs, and names for safe sharing. |
| `ScEntra-Large-Sample-*.ps1` | Generates synthetic datasets for demos/regressions. |
| `docs/MAINTENANCE.md` | (This file) architecture, troubleshooting, and contribution guidance. |

## Data Flow in Five Steps

```
Connect-ScEntraGraph ──► Invoke-ScEntraAnalysis ──► Private collectors ──► Get-ScEntraEscalationPaths ──► Export-ScEntraReport ──► HTML + JSON artifacts
                                                                                    │
                                                                                    └──► calls New-ScEntraGraphData
                                                                                    └──► uses ReportBuilder.ps1
```

1. **Authentication** (`Connect-ScEntraGraph.ps1`) uses Az context, Azure CLI, or device code flow to capture a Graph token with the required scopes.

2. **Orchestration** (`Invoke-ScEntraAnalysis.ps1`) coordinates the entire workflow:
   - Calls all private collectors in sequence: `Get-ScEntraUsersAndGroups`, `Get-ScEntraServicePrincipals`, `Get-ScEntraAppRegistrations`, `Get-ScEntraRoleAssignments`, `Get-ScEntraPIMAssignments`.
   - Each collector calls Graph REST endpoints and normalizes output into PowerShell objects.

3. **Escalation analysis** (`Get-ScEntraEscalationPaths.ps1`) receives all collected data and:
   - Analyzes ownership chains, group memberships, role assignments, and PIM eligibility.
   - Identifies privilege escalation paths.
   - Calls `New-ScEntraGraphData.ps1` to build graph nodes and edges with risk metadata.
   - Returns both `Risks` array and `GraphData` hashtable.

4. **Report generation** (`Export-ScEntraReport.ps1`) receives all data and:
   - Generates statistics and risk distributions.
   - Calls `New-ScEntraReportDocument` which uses `ReportBuilder.ps1` template to:
     - Embed the dataset as JSON.
     - Instantiate vis-network with clustering and highlighting logic.
     - Render HTML/CSS/JS with dark mode default, 2× selected node sizing, and enriched user metadata.
   - Writes both HTML and JSON artifacts to disk with matching timestamps.

5. **Automation helpers** (`Generate-ReportFromJson.ps1`, `Invoke-JsonAnonymizer.ps1`) let maintainers validate UI changes against frozen datasets or anonymize outputs before sharing.

## Key Functions and Expectations

| Function | Location | Summary |
| --- | --- | --- |
| `Connect-ScEntraGraph` | `Public/Connect-ScEntraGraph.ps1` | Authenticates, validates scopes, exposes `scopes`, `tenant`, and token reuse helpers. Must never silently downgrade permissions. **Public API.** |
| `Invoke-ScEntraAnalysis` | `Public/Invoke-ScEntraAnalysis.ps1` | Orchestrates collection, calls `New-ScEntraGraphData`, writes HTML/JSON, and returns an object for automation. **Public API.** |
| `Get-ScEntraUsersAndGroups` | `Private/Get-ScEntraUsersAndGroups.ps1` | Fetches users/groups, enriches hybrid flags, and captures metadata such as `lastPasswordChangeDateTime`. Any new user fields should be surfaced here to keep the pipeline single-sourced. **Internal only.** |
| `Get-ScEntraServicePrincipals` | `Private/Get-ScEntraServicePrincipals.ps1` | Retrieves all service principals with app metadata. **Internal only.** |
| `Get-ScEntraAppRegistrations` | `Private/Get-ScEntraAppRegistrations.ps1` | Fetches registered applications and their API permissions. **Internal only.** |
| `Get-ScEntraRoleAssignments` | `Private/Get-ScEntraRoleAssignments.ps1` | Collects active role assignments. **Internal only.** |
| `Get-ScEntraPIMAssignments` | `Private/Get-ScEntraPIMAssignments.ps1` | Retrieves PIM eligible and time-limited role assignments. **Internal only.** |
| `Get-ScEntraEscalationPaths` | `Private/Get-ScEntraEscalationPaths.ps1` | Analyzes ownership chains, group memberships, and role assignments to identify escalation paths. Calls `New-ScEntraGraphData` internally. **Internal only.** |
| `New-ScEntraGraphData` | `Private/New-ScEntraGraphData.ps1` | Central graph builder. Maintains helper functions (`$ensureUserNode`, permission mapping, escalation lookups). All new data types should be funneled through helper functions to avoid duplication. **Internal only.** |
| `ReportBuilder` | `Private/ReportBuilder.ps1` | HTML template + JS logic. Stores original node/edge styles, applies highlighting, grouping, dark theme, and modal layout. Changes here affect every generated report, including legacy JSON replays. **Internal only.** |
| `Export-ScEntraReport` | `Public/Export-ScEntraReport.ps1` | Generates statistics, calls `New-ScEntraReportDocument` (which uses `ReportBuilder.ps1`), and writes HTML/JSON artifacts. Not exported from module despite being in Public/ folder. **Internal only.** |
| `Invoke-JsonAnonymizer` | Root script | Hashes identifiers consistently. Extend this script if new sensitive fields are added to the JSON output. **Standalone utility.** |

## Extending or Updating Logic

### Adding New Graph Fields to Entra ID Data
1. **Identify the collector**: For users/groups, edit `Get-ScEntraUsersAndGroups.ps1`; for service principals, edit `Get-ScEntraServicePrincipals.ps1`; for apps, edit `Get-ScEntraAppRegistrations.ps1`.
2. **Update the `$select` query**: Add the new field to the OData select statement (e.g., `$select=id,displayName,newField`).
3. **Centralize in graph builder**: Pass new properties into `New-ScEntraGraphData.ps1` via helper functions (`$ensureUserNode`, `$ensureServicePrincipalNode`, etc.). This ensures every code path (direct assignments, nested memberships, ownership edges) inherits the same metadata.
4. **Surface in UI**: Reference the new property in `ReportBuilder.ps1` within tooltips, detail panels, filters, or clustering logic.
5. **Test backward compatibility**: Regenerate a report from an existing JSON (missing the new field) to ensure the UI degrades gracefully with null checks.

### Adding New Attack Paths (Escalation Rules)
Attack paths define how a low-privilege principal can escalate to higher privileges. ScEntra models these as edges with risk metadata.

**Step-by-step:**

1. **Define the risk condition** in `New-ScEntraGraphData.ps1`:
   - Locate `$permissionEscalationTargets` (maps dangerous Graph API permissions to roles they can compromise).
   - Add new entries, e.g., `'RoleManagement.ReadWrite.Directory' = @('Global Administrator', 'Privileged Role Administrator')`.
   - Or define custom logic in the escalation loop (e.g., "any user who owns a PIM-enabled group can escalate to roles assigned to that group").

2. **Create the edge** with risk metadata:
   ```powershell
   $edges += @{
       from = $attackerNodeId
       to = $targetNodeId
       label = 'can escalate via'
       color = '#ff6b6b'
       dashes = $true
       escalationRisk = @{
           Severity = 'High'
           Path = "$attackerName -> $targetName"
           Description = 'User owns PIM-enabled group with Global Admin assignment'
       }
   }
   ```

3. **Label high-privilege targets**: Update `$highPrivilegeRoles` if the target role isn't already flagged. This affects filtering in the HTML report.

4. **Document the rule**: Add a comment in `New-ScEntraGraphData.ps1` explaining the attack vector (e.g., "Group owners can add themselves as members, inheriting PIM eligibility").

5. **Test**: Run `Invoke-ScEntraAnalysis` against a test tenant (or synthetic data) where the condition exists. Verify:
   - The edge appears in the graph.
   - The risk shows in `$results.EscalationRisks`.
   - Filtering by "High Severity" highlights the path.

**Example addition:**
```powershell
# NEW RULE: Users with UserAuthenticationMethod.ReadWrite.All can reset MFA for admins
foreach ($appPermission in $appPermissions | Where-Object { $_.permission -eq 'UserAuthenticationMethod.ReadWrite.All' }) {
    foreach ($role in $roleAssignments | Where-Object { $_.RoleId -in $highPrivilegeRoles.Keys }) {
        $edges += @{
            from = $appPermission.appId
            to = $role.MemberId
            label = 'can reset MFA for'
            color = '#ff6b6b'
            escalationRisk = @{
                Severity = 'Critical'
                Path = "$($appPermission.appName) -> $($role.MemberName)"
                Description = 'App can disable MFA on privileged accounts'
            }
        }
    }
}
```

### Onboarding New Data Sources (e.g., Azure Resources)
To incorporate Azure subscription data (VMs, Key Vaults, role assignments at subscription/resource group scope):

**Architecture overview:**
- Entra ID uses Microsoft Graph (`graph.microsoft.com`).
- Azure uses Azure Resource Manager (`management.azure.com`).
- Both share Azure AD/Entra authentication but have separate REST APIs.

**Implementation steps:**

1. **Create a new collector** in `Private/`, e.g., `Get-ScEntraAzureResources.ps1`:
   ```powershell
   function Get-ScEntraAzureResources {
       param([string]$SubscriptionId, [string]$AccessToken)
       
       $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resources?api-version=2021-04-01"
       $headers = @{ Authorization = "Bearer $AccessToken" }
       
       $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
       return $response.value
   }
   ```

2. **Acquire an ARM token**: Update `Connect-ScEntraGraph.ps1` (or create a separate `Connect-ScEntraAzure` helper) to fetch a token for `https://management.azure.com`:
   ```powershell
   $armToken = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
   ```

3. **Map Azure identities to Entra principals**:
   - Azure role assignments reference `principalId` (an Entra object ID).
   - Correlate these with `$results.Users`, `$results.ServicePrincipals`, or `$results.Groups`.
   - Example:
     ```powershell
     $azRoleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId"
     foreach ($assignment in $azRoleAssignments) {
         $principal = $results.Users + $results.ServicePrincipals | Where-Object { $_.id -eq $assignment.PrincipalId }
         if ($principal) {
             # Create node for Azure resource and edge from principal
         }
     }
     ```

4. **Extend the graph builder**: In `New-ScEntraGraphData.ps1`, add helper functions like `$ensureAzureResourceNode`:
   ```powershell
   $ensureAzureResourceNode = {
       param($resourceId, $resourceName, $resourceType)
       if (-not $nodeIndex.ContainsKey($resourceId)) {
           $nodes += @{
               id = $resourceId
               label = $resourceName
               title = "$resourceType\n$resourceId"
               shape = 'box'
               color = @{ background = '#3b82f6'; border = '#1e40af' }
               group = 'AzureResource'
           }
           $nodeIndex[$resourceId] = $nodes.Count - 1
       }
   }
   ```

5. **Define escalation paths**: Identify risky Azure permissions (e.g., `Contributor` on a Key Vault containing admin credentials, `Owner` on a subscription housing identity resources).
   - Add edges with `escalationRisk` metadata when a low-privilege Entra user has high Azure privileges.

6. **Update orchestration**: Modify `Invoke-ScEntraAnalysis` to:
   - Accept `-IncludeAzure` switch.
   - Call the new collector(s).
   - Pass Azure data into `New-ScEntraGraphData`.

7. **UI considerations**:
   - Azure nodes use a different shape/color for visual distinction.
   - Add a filter toggle in `ReportBuilder.ps1` (e.g., "Show Azure Resources").
   - Include Azure-specific metadata in detail modals (subscription ID, resource group, location).

8. **Testing**:
   - Run against a test subscription with known role assignments.
   - Verify cross-cloud correlations (e.g., Entra user → Azure Contributor → Key Vault).
   - Regenerate reports from cached JSON to ensure UI handles mixed datasets.

**Example integration:**
```powershell
# In Invoke-ScEntraAnalysis.ps1
if ($IncludeAzure) {
    $armToken = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    $azureData = @{
        Resources = Get-ScEntraAzureResources -SubscriptionId $SubscriptionId -AccessToken $armToken
        RoleAssignments = Get-AzRoleAssignment
    }
    $graphData = New-ScEntraGraphData -Users $users -Groups $groups -Azure $azureData
}
```

**Permissions required:**
- Microsoft Graph: existing scopes (User.Read.All, etc.).
- Azure: `Reader` at subscription scope (or `Owner` to map RBAC assignments).
- Update `Connect-ScEntraGraph` to validate both token audiences if supporting hybrid scenarios.

### Adjusting Visualization Behavior
- **Node sizing / highlighting:** edit `highlightPath` and `resetHighlight` in `ReportBuilder.ps1`. Always persist the baseline in `originalNodeStyles` first so toggling filters restores the default size.
- **Themes:** the template reads CSS variables from `body[data-theme]`. To change defaults, modify the initialization block near the bottom of `ReportBuilder.ps1` (currently defaulting to dark unless the user previously saved a preference).
- **Clustering / focus behavior:** update the `groupMatchingNodes` and `focusOnSearchMatch` helpers. Maintain stored positions in `originalNodePositions` to keep layout organic when toggling filters.

### Working with Risk Logic
- Escalation definitions live inside `New-ScEntraGraphData.ps1` (`$permissionEscalationTargets`). Add new entries to flag risky permissions.
- Role severity is defined by `$highPrivilegeRoles`. Update this list when Entra introduces new tiers.
- When adding a risk type, ensure `Invoke-ScEntraAnalysis` includes it in the `EscalationRisks` export and that the HTML template has a corresponding legend icon.

## Testing & Validation Checklist

1. **Unit-style validations:**
   - Run `Invoke-ScEntraAnalysis -SkipConnection` against a cached context.
   - Use `Generate-ReportFromJson.ps1` on `ScEntra-Large-Sample-Report.json` to test UI-only changes.
2. **Sanitization:**
   - Execute `Invoke-JsonAnonymizer.ps1` on a recent JSON and open the regenerated HTML to confirm replacements look reasonable.
3. **Static analysis:**
   - Run `pwsh -NoLogo -Command "Invoke-ScriptAnalyzer -Path ."` (optional but encouraged before pull requests).
4. **Git hygiene:**
   - Remove `.DS_Store` or regenerated HTML/JSON artifacts before committing (`git status` should show only intentional changes).

## Troubleshooting for Maintainers

| Issue | Diagnosis / Fix |
| --- | --- |
| Graph calls returning partial data | Inspect verbose logs (`$VerbosePreference = 'Continue'`). Most collectors paginate via `Get-AllGraphItems`; verify `@odata.nextLink` handling if counts look low. |
| `vis-network` errors in console | Open the generated HTML in DevTools; ensure dataset arrays are valid. Typically caused by null IDs or missing `originalNodeStyles` entries when new node types are introduced. |
| Selected nodes not resetting | Confirm `originalNodeStyles` captures every property you change. Both highlight and reset flows must update `size`, `font`, `shadow`, etc. |
| Anonymizer misses new fields | Extend the mapping in `Invoke-JsonAnonymizer.ps1` to cover any additional properties that carry tenant identifiers. |
| Theme toggle stuck | The toggle stores `scEntra-theme` in `localStorage`. Clear storage or bump the key name when distributing breaking theme changes. |

## Release & Contribution Tips
-
- Document new parameters or behaviors in `QUICKSTART.md` (user-facing) and update this maintenance file if internal workflows change.
- Tag UI-affecting commits with a short summary of what changed in `ReportBuilder.ps1` so downstream consumers can regenerate HTML knowing why.
- Encourage contributors to attach regenerated reports (zipped) to pull requests for visual inspection, but keep them out of source control.
- When adding dependencies, call them out in the prerequisites section and ensure the module checks for their presence at runtime.

For any architectural proposal that changes data flow (e.g., storing intermediate state, adding caching), include a diagram similar to the “Data Flow” section above to keep reviewers aligned.
