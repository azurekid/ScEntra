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
  - Escalation paths from SPNs and App Registrations
  - Owner and member relationships for all entities

- 📊 **Rich Visualization**:
  - Interactive HTML reports with charts
  - **Bloodhound-style graph visualization** showing escalation paths
  - Interactive network graph with draggable nodes
  - Color-coded entities (users, groups, roles, SPNs, apps)
  - Visual representation of relationships and escalation paths
  - JSON export for programmatic analysis
  - Risk severity categorization

- ⏱️ **Real-time Progress Tracking**:
  - Live progress indicators during long-running operations
  - Pagination progress with item counts
  - Current operation and item name display
  - Percentage-based progress bars
  - Multi-phase operation tracking

- ⚡ **Performance Optimized for Large Environments**:
  - Graph API batch processing (up to 20 requests per batch)
  - Selective data fetching - only retrieves member details for security-relevant groups
  - Minimized API calls to reduce detection and improve speed
  - Smart filtering of groups before analysis (role-enabled, assigned to roles, or in PIM)

## Prerequisites

- PowerShell 7.0 or later
- Authentication method (choose one):
  - Azure PowerShell (`Az` module) - Recommended
  - Azure CLI
  - Direct access token

**Note:** This module uses Microsoft Graph REST API endpoints directly and does not require the Microsoft Graph PowerShell SDK modules.

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

## Authentication

ScEntra uses Microsoft Graph REST API and supports multiple authentication methods:

### Method 1: Azure PowerShell (Recommended)

```powershell
# Install Azure PowerShell if not already installed
Install-Module -Name Az -Scope CurrentUser

# Connect to Azure
Connect-AzAccount

# Import and run ScEntra
Import-Module ./ScEntra.psd1
Invoke-ScEntraAnalysis
```

### Method 2: Azure CLI

```bash
# Install Azure CLI if not already installed
# See: https://docs.microsoft.com/cli/azure/install-azure-cli

# Login to Azure
az login
```

```powershell
# Import and run ScEntra
Import-Module ./ScEntra.psd1
Invoke-ScEntraAnalysis
```

### Method 3: Access Token

```powershell
# Obtain an access token from your authentication provider
$token = "eyJ0eXAiOiJKV1QiLCJhbGc..."

# Connect using the token
Import-Module ./ScEntra.psd1
Connect-ScEntraGraph -AccessToken $token

# Run analysis
Invoke-ScEntraAnalysis -SkipConnection
```

## Quick Start

### Basic Usage

```powershell
# Authenticate using Azure PowerShell
Connect-AzAccount

# Import the module
Import-Module ./ScEntra.psd1

# Run the complete analysis
Invoke-ScEntraAnalysis
```

### Advanced Usage

```powershell
# Authenticate using Azure PowerShell or Azure CLI first
Connect-AzAccount
# or
# az login

# Import the module
Import-Module ./ScEntra.psd1

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
   - **Interactive escalation path graph** (Bloodhound-style visualization)
   - Network diagram showing users, groups, roles, service principals, and app registrations
   - Visual representation of escalation paths and relationships
   - Charts showing role distribution and risk types
   - Detailed risk table with severity indicators

2. **JSON Data** (`ScEntra-Report-{timestamp}.json`):
   - Complete data export for programmatic analysis
   - All collected inventory data
   - Identified risks with full details
   - Graph data structure (nodes and edges)

## Risk Types

ScEntra identifies the following risk types:

- **RoleEnabledGroup**: Groups assigned to roles with privileged access
- **NestedGroupMembership**: Privilege escalation through nested group memberships  
- **ServicePrincipalOwnership**: Service principals with role assignments and multiple owners (including escalation paths from owners)
- **AppRegistrationOwnership**: App registrations with excessive owners (including paths to linked service principals)
- **MultiplePIMRoles**: Principals with multiple PIM role assignments

## Graph Visualization

The interactive graph visualization provides a Bloodhound-style view of escalation paths:

**Node Types:**
- 🟢 **Users** (Green) - User accounts
- 🔵 **Groups** (Blue) - Security and role-enabled groups
- 🔴 **Roles** (Red/Diamond) - Entra ID directory roles
- 🟣 **Service Principals** (Purple) - Application service principals
- 🟠 **Applications** (Orange) - App registrations

**Edge Types:**
- **has_role** (Solid) - Direct or PIM role assignments
- **member_of** (Solid) - Group membership
- **owns** (Dashed) - Ownership relationship
- **has_service_principal** - Link between app registration and its service principal

**Features:**
- Drag nodes to rearrange the graph
- Zoom and pan to explore different areas
- Click on nodes to highlight connections
- Hover over nodes to see details
- PIM assignments shown with dashed edges

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

When you run `Invoke-ScEntraAnalysis`, you'll see progress output with real-time progress indicators:

```
╔═══════════════════════════════════════════════════════════╗
║                    SCENTRA                                ║
║        Scan Entra for Risk & Escalation Paths            ║
╚═══════════════════════════════════════════════════════════╝

[1/5] 📋 Collecting Inventory...
============================================================
Retrieving users from Entra ID [Fetching page 3 (retrieved 300 items so far)]
Retrieved 150 users
Retrieving groups from Entra ID [Retrieved 45 groups]
Fetching group member counts [Processing group 15 of 45 - Engineering Team] 33%
Retrieved 45 groups
Retrieved 30 service principals
Retrieved 25 app registrations

[2/5] 👑 Enumerating Role Assignments...
============================================================
Enumerating role assignments [Processing role 3 of 12 - Security Reader] 25%
Retrieved 28 direct role assignments across 12 roles

[3/5] 🔐 Checking PIM Assignments...
============================================================
Retrieving PIM assignments [Fetching active role assignments]
Retrieved 15 PIM assignments (10 eligible, 5 active)

[4/5] 🔍 Analyzing Escalation Paths...
============================================================
Found 5 role-enabled groups
Analyzing escalation paths [Analyzing role-enabled group 2 of 5] 40%
Analyzing nested group memberships [Processing group 3 of 8] 37%
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

**Using Azure PowerShell:**
```powershell
# Disconnect and reconnect
Disconnect-AzAccount
Connect-AzAccount

# Verify connection
Get-AzContext
```

**Using Azure CLI:**
```bash
# Logout and login again
az logout
az login

# Verify connection
az account show
```

### Permission Errors

Ensure your account has the necessary permissions to read the required data. Some operations may require Global Reader or higher privileges.

The following Microsoft Graph API permissions are required:
- `User.Read.All` - Read all users
- `Group.Read.All` - Read all groups
- `Application.Read.All` - Read applications and service principals
- `RoleManagement.Read.Directory` - Read directory role assignments
- `RoleEligibilitySchedule.Read.Directory` - Read PIM eligible assignments
- `RoleAssignmentSchedule.Read.Directory` - Read PIM active assignments

### Module Loading Issues

If the module fails to load:

```powershell
# Verify PowerShell version (requires 7.0 or later)
$PSVersionTable.PSVersion

# Check module files exist
Test-Path ./ScEntra.psd1
Test-Path ./ScEntra.psm1

# Import with verbose output for troubleshooting
Import-Module ./ScEntra.psd1 -Verbose
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
