# ScEntra

🔐 **Scan Entra for risk in role assignments and escalation paths**

A PowerShell module for comprehensive security analysis of Microsoft Entra ID (formerly Azure AD) environments. ScEntra provides detailed inventory of identity objects, role assignments, and identifies potential privilege escalation paths.

## Features

- 📋 **Comprehensive Inventory**: Collect complete information about:
  - Users
  - Groups (including role-enabled groups)
  - Service Principals
  - App Registrations

- 👑 **Role Assignment Enumeration**:
  - Direct role assignments
  - PIM (Privileged Identity Management) assignments (both active and eligible)
  - Role-enabled group memberships

- 🔍 **Escalation Path Analysis**:
  - Nested group memberships leading to role elevation
  - Role-enabled group risks
  - Service Principal ownership analysis
  - App Registration ownership patterns
  - Multiple PIM role assignments

- 📊 **Rich Visualization**:
  - Interactive HTML reports with charts
  - JSON export for programmatic analysis
  - Risk severity categorization

## Prerequisites

- PowerShell 7.0 or later
- Microsoft Graph PowerShell SDK modules:
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Users
  - Microsoft.Graph.Groups
  - Microsoft.Graph.Applications
  - Microsoft.Graph.Identity.DirectoryManagement
  - Microsoft.Graph.Identity.Governance

## Installation

### Option 1: Clone the repository

```powershell
git clone https://github.com/azurekid/ScEntra.git
cd ScEntra
Import-Module ./ScEntra.psd1
```

### Option 2: Direct download

Download the `ScEntra.psd1` and `ScEntra.psm1` files and import the module:

```powershell
Import-Module ./ScEntra.psd1
```

## Quick Start

### Basic Usage

```powershell
# Import the module
Import-Module ./ScEntra.psd1

# Run the complete analysis (will prompt for authentication)
Invoke-ScEntraAnalysis
```

### Advanced Usage

```powershell
# Connect to Microsoft Graph with required scopes first
Connect-MgGraph -Scopes @(
    "User.Read.All"
    "Group.Read.All"
    "Application.Read.All"
    "RoleManagement.Read.Directory"
    "RoleEligibilitySchedule.Read.Directory"
    "RoleAssignmentSchedule.Read.Directory"
)

# Run analysis with custom output path
Invoke-ScEntraAnalysis -OutputPath "C:\Reports\entra-security-analysis.html" -SkipConnection
```

### Individual Functions

You can also use individual functions for specific tasks:

```powershell
# Get all users
$users = Get-ScEntraUsers

# Get all groups
$groups = Get-ScEntraGroups

# Get role assignments
$roles = Get-ScEntraRoleAssignments

# Get PIM assignments
$pim = Get-ScEntraPIMAssignments

# Analyze escalation paths
$risks = Get-ScEntraEscalationPaths -Users $users -Groups $groups -RoleAssignments $roles -PIMAssignments $pim

# Export custom report
Export-ScEntraReport -Users $users -Groups $groups -RoleAssignments $roles -OutputPath "./my-report.html"
```

## Functions

### `Invoke-ScEntraAnalysis`
Main orchestration function that performs complete security analysis and generates reports.

**Parameters:**
- `-OutputPath` (optional): Path for the HTML report (default: `./ScEntra-Report-{timestamp}.html`)
- `-SkipConnection` (optional): Skip connection check if already connected to Graph

### `Get-ScEntraUsers`
Retrieves all users from Entra ID with their key properties.

### `Get-ScEntraGroups`
Retrieves all groups including role-enabled status and member counts.

### `Get-ScEntraServicePrincipals`
Retrieves all service principals in the tenant.

### `Get-ScEntraAppRegistrations`
Retrieves all application registrations.

### `Get-ScEntraRoleAssignments`
Enumerates all direct directory role assignments.

### `Get-ScEntraPIMAssignments`
Retrieves PIM role assignments (both eligible and active).

### `Get-ScEntraEscalationPaths`
Analyzes the collected data to identify privilege escalation risks.

**Parameters:**
- `-Users`: Array of users
- `-Groups`: Array of groups
- `-RoleAssignments`: Array of role assignments
- `-PIMAssignments`: Array of PIM assignments
- `-ServicePrincipals`: Array of service principals
- `-AppRegistrations`: Array of app registrations

### `Export-ScEntraReport`
Generates HTML and JSON reports from analysis data.

**Parameters:**
- `-Users`: Array of users
- `-Groups`: Array of groups
- `-ServicePrincipals`: Array of service principals
- `-AppRegistrations`: Array of app registrations
- `-RoleAssignments`: Array of role assignments
- `-PIMAssignments`: Array of PIM assignments
- `-EscalationRisks`: Array of identified risks
- `-OutputPath`: Path for the HTML report

## Output

The analysis generates two files:

1. **HTML Report** (`ScEntra-Report-{timestamp}.html`):
   - Interactive dashboard with statistics
   - Charts showing role distribution and risk types
   - Detailed risk table with severity indicators

2. **JSON Data** (`ScEntra-Report-{timestamp}.json`):
   - Complete data export for programmatic analysis
   - All collected inventory data
   - Identified risks with full details

## Risk Types

ScEntra identifies the following risk types:

- **RoleEnabledGroup**: Groups assigned to roles with privileged access
- **NestedGroupMembership**: Privilege escalation through nested group memberships
- **ServicePrincipalOwnership**: Service principals with role assignments and multiple owners
- **AppRegistrationOwnership**: App registrations with excessive owners
- **MultiplePIMRoles**: Principals with multiple PIM role assignments

## Severity Levels

- 🔴 **High**: Critical risks requiring immediate attention
- 🟡 **Medium**: Moderate risks that should be reviewed
- 🟢 **Low**: Minor issues or informational findings

## Required Permissions

The following Microsoft Graph API permissions are required:

- `User.Read.All` - Read all users
- `Group.Read.All` - Read all groups
- `Application.Read.All` - Read applications and service principals
- `RoleManagement.Read.Directory` - Read directory role assignments
- `RoleEligibilitySchedule.Read.Directory` - Read PIM eligible assignments
- `RoleAssignmentSchedule.Read.Directory` - Read PIM active assignments

## Example Output

When you run `Invoke-ScEntraAnalysis`, you'll see progress output like:

```
╔═══════════════════════════════════════════════════════════╗
║                    SCENTRA                                ║
║        Scan Entra for Risk & Escalation Paths            ║
╚═══════════════════════════════════════════════════════════╝

[1/5] 📋 Collecting Inventory...
============================================================
Retrieved 150 users
Retrieved 45 groups
Retrieved 30 service principals
Retrieved 25 app registrations

[2/5] 👑 Enumerating Role Assignments...
============================================================
Retrieved 28 direct role assignments across 12 roles

[3/5] 🔐 Checking PIM Assignments...
============================================================
Retrieved 15 PIM assignments (10 eligible, 5 active)

[4/5] 🔍 Analyzing Escalation Paths...
============================================================
Found 5 role-enabled groups
Identified 8 potential escalation risks

[5/5] 📊 Generating Report...
============================================================
Report generated successfully: ./ScEntra-Report-20251118-105030.html
JSON data exported to: ./ScEntra-Report-20251118-105030.json

============================================================
✓ Analysis Complete!
============================================================

Summary:
  • Users: 150
  • Groups: 45
  • Service Principals: 30
  • App Registrations: 25
  • Role Assignments: 28
  • PIM Assignments: 15
  • Escalation Risks: 8

Report Location: ./ScEntra-Report-20251118-105030.html
Duration: 02:45
```

## Troubleshooting

### Authentication Issues

If you encounter authentication errors:

```powershell
# Disconnect and reconnect
Disconnect-MgGraph
Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "Application.Read.All", "RoleManagement.Read.Directory"
```

### Permission Errors

Ensure your account has the necessary permissions to read the required data. Some operations may require Global Reader or higher privileges.

### Module Loading Issues

If the module fails to load:

```powershell
# Check if required modules are installed
Get-Module -ListAvailable Microsoft.Graph*

# Install missing modules
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is provided as-is for security analysis purposes.

## Disclaimer

This tool is designed for authorized security assessments only. Always ensure you have proper authorization before running security scans against any Entra ID tenant.

## Author

ScEntra Contributors

## Version History

- **v1.0.0** (2025-11-18): Initial release
  - Complete inventory collection
  - Role assignment enumeration (direct and PIM)
  - Escalation path analysis
  - HTML and JSON report generation
