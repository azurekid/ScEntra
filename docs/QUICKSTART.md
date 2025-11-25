git clone https://github.com/azurekid/ScEntra.git
# ScEntra Operations & Quick Start Guide

ScEntra inventories Entra ID objects, models escalation paths, and generates interactive reports that default to dark mode, highlight user metadata (UPN, creation time, password history), and emphasize selected entities. This guide rebuilds the documentation around the current experience and links to the deeper maintenance notes for contributors.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Authentication Options](#authentication-options)
4. [Running Analyses](#running-analyses)
5. [Working with Output Files](#working-with-output-files)
6. [Sample and Offline Data](#sample-and-offline-data)
7. [Common Operational Tasks](#common-operational-tasks)
8. [Troubleshooting](#troubleshooting)
9. [Maintainer Notes](#maintainer-notes)

## Prerequisites
- PowerShell 7.0+ on macOS, Linux, or Windows.
- Microsoft Graph credentials with, at minimum, `User.Read.All`, `Group.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory`, `RoleEligibilitySchedule.Read.Directory`, and `RoleAssignmentSchedule.Read.Directory`.
- Optional but recommended: `Az` PowerShell module or Azure CLI for acquiring tokens.

## Installation
```powershell
git clone https://github.com/azurekid/ScEntra.git
cd ScEntra
Import-Module ./ScEntra.psd1
```
Re-import with `-Force` after pulling changes.

## Authentication Options
ScEntra uses Microsoft Graph REST endpoints directly. Pick one of the following before running any workflow:

### Azure PowerShell Context (recommended)
```powershell
Install-Module Az -Scope CurrentUser   # once per machine
Connect-AzAccount                      # interactive device or browser flow
```

### Azure CLI Context
```bash
az login
```

### Device Code Flow via `Connect-ScEntraGraph`
```powershell
Connect-ScEntraGraph -UseDeviceCode    # requests only the scopes ScEntra needs
```

Provide `-AccessToken` to `Connect-ScEntraGraph` if you already have an app-only Graph token that includes the required scopes.

## Running Analyses

### Full pipeline (inventory → analysis → report)
```powershell
Import-Module ./ScEntra.psd1
Invoke-ScEntraAnalysis
```
Generates timestamped HTML and JSON in the repo root. Use `-OutputPath` to write the HTML elsewhere or `-OutputJsonPath` for custom JSON locations.

### Skipping the connection check
If you already authenticated with Az or Azure CLI and do not want the module to re-check:
```powershell
Invoke-ScEntraAnalysis -SkipConnection
```

### Using existing JSON (no new Graph calls)
```powershell
./Generate-ReportFromJson.ps1 -JsonPath ./ScEntra-Report-20251123-111337.json
```
This rebuilds an HTML report with the latest UI code (dark theme default, enlarged selection halo, expanded user metadata).

### Sharing or sanitizing output
```powershell
./Invoke-JsonAnonymizer.ps1 -InputPath ./ScEntra-Report-20251123-111337.json -OutputPath ./anonymized.json
```
Use the anonymized JSON with `Generate-ReportFromJson.ps1` to produce a sanitized HTML artifact for demos.

## Working with Output Files
- **HTML** (`ScEntra-Report-YYYYMMDD-HHMMSS.html`): interactive, dark by default, includes filters, grouping, escalation focus modes, and a modal showing per-node metadata (UPN, account status, source sync flag, created time, last password change).
- **JSON** (`ScEntra-Report-YYYYMMDD-HHMMSS.json`): structured data, consumable by custom tooling or for regenerating HTML later.
- Both files share the same timestamp stem. Keep pairs together for forensic or diff workflows.

## Sample and Offline Data

| Script | Purpose | Key Facts |
| --- | --- | --- |
| `Generate-LargeSampleReport.ps1` | Builds a 200-user, 150+ risk synthetic tenant | Exercises every visualization and escalation rule. |
| `Generate-ReportFromJson.ps1` | Converts any saved JSON into HTML | Handy when testing UI changes with a frozen dataset. |

These flows require no Entra access. Use them for training, UI regression testing, or community demos.

## Common Operational Tasks

### Analyze and filter results
```powershell
# Run full analysis
$results = Invoke-ScEntraAnalysis

# Access collected data
$results.Users           # All users
$results.Groups          # All groups
$results.ServicePrincipals
$results.AppRegistrations
$results.RoleAssignments
$results.PIMAssignments
$results.EscalationRisks
```

### Export high-severity risks
```powershell
$results = Invoke-ScEntraAnalysis
$results.EscalationRisks | Where-Object Severity -eq 'High' |
    Export-Csv ./high-risks.csv -NoTypeInformation
```

### Filter role-enabled groups
```powershell
$results = Invoke-ScEntraAnalysis
$results.Groups | Where-Object { $_.isAssignableToRole } |
    Select-Object displayName, memberCount, isAssignableToRole
```

### Find users with multiple privileged roles
```powershell
$results = Invoke-ScEntraAnalysis
$results.RoleAssignments | Where-Object { $_.MemberType -eq 'user' } |
    Group-Object MemberId | Where-Object { $_.Count -gt 2 } |
    ForEach-Object {
        $userId = $_.Name
        $user = $results.Users | Where-Object { $_.id -eq $userId }
        [PSCustomObject]@{
            User = $user.displayName
            UPN = $user.userPrincipalName
            RoleCount = $_.Count
            Roles = ($_.Group.RoleName -join ', ')
        }
    }
```

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| Module fails to import | `Remove-Module ScEntra -ErrorAction SilentlyContinue; Import-Module ./ScEntra.psd1 -Force` |
| Authentication errors | Re-run `Connect-AzAccount` (or `az login`), then `Connect-ScEntraGraph -UseDeviceCode -SkipScopesCheck:$false` to re-validate permissions. |
| Missing Graph scopes | **ScEntra continues running with partial data when permissions are missing.** At the end of analysis, it displays a summary of missing permissions (e.g., PIM assignments skipped if `RoleEligibilitySchedule.Read.Directory` is unavailable). To collect complete data, ensure the signed-in principal has consented to `User.Read.All`, `Group.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory`, `RoleEligibilitySchedule.Read.Directory`, `RoleAssignmentSchedule.Read.Directory`, and `PrivilegedAccess.Read.AzureADGroup`. Sign in with Global Reader or higher and accept the consent prompt displayed by `Connect-ScEntraGraph -UseDeviceCode`. |
| Report shows stale UI | Re-run `Generate-ReportFromJson.ps1` against the existing JSON so the latest `ReportBuilder` template (dark mode, enhanced node sizing) is embedded. |
| JSON too sensitive to share | Run `Invoke-JsonAnonymizer.ps1` to replace identifiers; regenerate HTML from the sanitized JSON. |

For more intricate debugging (Graph throttling, pagination, etc.) see `docs/MAINTENANCE.md`.

## Maintainer Notes
Community contributors should read `docs/MAINTENANCE.md` for:
- Module architecture maps (data collection, analysis, visualization).
- Function-by-function expectations and testing hooks.
- Guidance for adding new Graph fields, risk heuristics, or UI affordances.
- Validation checklists and release hygiene.

Use `Get-Command -Module ScEntra` for a live list of exported functions (currently `Connect-ScEntraGraph` and `Invoke-ScEntraAnalysis`) and `Get-Help <FunctionName> -Detailed` for inline documentation.
