# ScEntra Quick Start Guide

## Prerequisites

Before using ScEntra, ensure you have:
- PowerShell 7.0 or later
- Azure PowerShell module (`Az`) or Azure CLI for authentication

## Installation

```powershell
# Clone the repository
git clone https://github.com/azurekid/ScEntra.git
cd ScEntra

# Import the module
Import-Module ./ScEntra.psd1
```

## Authentication

ScEntra uses Microsoft Graph REST API and requires authentication via Azure PowerShell or Azure CLI.

### Option 1: Azure PowerShell (Recommended)

```powershell
# Install Azure PowerShell (if not already installed)
Install-Module -Name Az -Scope CurrentUser

# Authenticate
Connect-AzAccount
```

### Option 2: Azure CLI

```bash
# Install Azure CLI (if not already installed)
# See: https://docs.microsoft.com/cli/azure/install-azure-cli

# Authenticate
az login
```

## Quick Analysis

### 1️⃣ Run Complete Analysis (Recommended)

```powershell
# After authenticating with Connect-AzAccount or az login:
Import-Module ./ScEntra.psd1

# This will:
# - Use your existing Azure authentication
# - Collect all inventory data
# - Analyze escalation paths
# - Generate HTML and JSON reports
Invoke-ScEntraAnalysis
```

### 2️⃣ Custom Output Location

```powershell
Invoke-ScEntraAnalysis -OutputPath "C:\Reports\MyEntraAnalysis.html"
```

### 3️⃣ Pre-authenticated Connection

```powershell
# Authenticate first
Connect-AzAccount
# or: az login

# Import module
Import-Module ./ScEntra.psd1

# Run analysis without checking connection again
Invoke-ScEntraAnalysis -SkipConnection
```

## Common Scenarios

### Find Role-Enabled Groups

```powershell
Import-Module ./ScEntra.psd1

# Authenticate first
Connect-AzAccount

# Get all groups
$groups = Get-ScEntraGroups

# Filter to role-enabled groups
$roleEnabledGroups = $groups | Where-Object { $_.isAssignableToRole -eq $true }

# Display
$roleEnabledGroups | Select-Object displayName, memberCount, isAssignableToRole | Format-Table
```

### Identify High-Risk Users

```powershell
# Get all data
$users = Get-ScEntraUsers
$roles = Get-ScEntraRoleAssignments

# Find users with multiple roles
$userRoles = $roles | Where-Object { $_.MemberType -eq 'user' } | 
    Group-Object -Property MemberId

$highRiskUsers = $userRoles | Where-Object { $_.Count -gt 2 }

foreach ($userRole in $highRiskUsers) {
    $user = $users | Where-Object { $_.id -eq $userRole.Name }
    if ($user) {
        Write-Host "$($user.displayName): $($userRole.Count) roles" -ForegroundColor Yellow
        $userRole.Group | ForEach-Object { Write-Host "  - $($_.RoleName)" }
    }
}
```

### Analyze Service Principal Risks

```powershell
$sps = Get-ScEntraServicePrincipals
$roles = Get-ScEntraRoleAssignments

# Find service principals with role assignments
$spRoles = $roles | Where-Object { $_.MemberType -match 'servicePrincipal' }

foreach ($spRole in $spRoles) {
    $sp = $sps | Where-Object { $_.id -eq $spRole.MemberId }
    if ($sp) {
        Write-Host "Service Principal: $($sp.displayName)" -ForegroundColor Cyan
        Write-Host "  Role: $($spRole.RoleName)" -ForegroundColor Yellow
    }
}
```

### Export Specific Data

```powershell
# Run full analysis
$results = Invoke-ScEntraAnalysis

# Export high severity risks to CSV
$results.EscalationRisks | 
    Where-Object { $_.Severity -eq 'High' } |
    Export-Csv -Path "./high-risks.csv" -NoTypeInformation

# Export all role assignments to JSON
$results.RoleAssignments | 
    ConvertTo-Json -Depth 10 | 
    Out-File "./role-assignments.json"

# Export PIM assignments to CSV
$results.PIMAssignments | 
    Export-Csv -Path "./pim-assignments.csv" -NoTypeInformation
```

### Check PIM Eligible Assignments

```powershell
$pim = Get-ScEntraPIMAssignments

# Filter eligible assignments
$eligible = $pim | Where-Object { $_.AssignmentType -eq 'PIM-Eligible' }

Write-Host "Eligible PIM Assignments: $($eligible.Count)" -ForegroundColor Cyan

# Group by principal
$byPrincipal = $eligible | Group-Object -Property PrincipalId

foreach ($group in $byPrincipal) {
    Write-Host "`nPrincipal: $($group.Name)" -ForegroundColor Yellow
    $group.Group | ForEach-Object {
        Write-Host "  - $($_.RoleName)" -ForegroundColor White
    }
}
```

### Find Nested Group Memberships

```powershell
# Note: You can check nested memberships using the REST API
# The module's escalation path analysis already includes this check

# Run full analysis to see nested group risks
$results = Invoke-ScEntraAnalysis

# Filter for nested group membership risks
$nestedRisks = $results.EscalationRisks | 
    Where-Object { $_.RiskType -eq 'NestedGroupMembership' }

foreach ($risk in $nestedRisks) {
    Write-Host "Group: $($risk.GroupName)" -ForegroundColor Yellow
    Write-Host "  Role: $($risk.RoleName)" -ForegroundColor Cyan
    Write-Host "  Direct Members: $($risk.DirectMembers)" -ForegroundColor Green
    Write-Host "  Nested Members: $($risk.NestedMembers)" -ForegroundColor Yellow
}
```

## Generate Sample Report (No Authentication Needed)

```powershell
# Generate a sample report with mock data
./Generate-SampleReport.ps1

# Open the generated report
Invoke-Item ./ScEntra-Sample-Report.html
```

## Troubleshooting

### Module Won't Load

```powershell
# Ensure you're in the correct directory
cd /path/to/ScEntra

# Force reload
Remove-Module ScEntra -ErrorAction SilentlyContinue
Import-Module ./ScEntra.psd1 -Force
```

### Authentication Issues

**Azure PowerShell:**
```powershell
# Disconnect and reconnect
Disconnect-AzAccount
Connect-AzAccount

# Verify connection
Get-AzContext
```

**Azure CLI:**
```bash
# Logout and login again
az logout
az login

# Verify connection
az account show
```

### Missing Permissions

If you get permission errors, ensure your account has the required Microsoft Graph API permissions:
- `User.Read.All` - Read all users
- `Group.Read.All` - Read all groups
- `Application.Read.All` - Read applications and service principals
- `RoleManagement.Read.Directory` - Read directory role assignments
- `RoleEligibilitySchedule.Read.Directory` - Read PIM eligible assignments
- `RoleAssignmentSchedule.Read.Directory` - Read PIM active assignments

Your account typically needs Global Reader role or equivalent permissions.

## Output Files

After running `Invoke-ScEntraAnalysis`, you'll get:

1. **HTML Report** (`ScEntra-Report-YYYYMMDD-HHMMSS.html`)
   - Interactive dashboard with charts
   - Risk tables with severity indicators
   - Statistics cards

2. **JSON Data** (`ScEntra-Report-YYYYMMDD-HHMMSS.json`)
   - Complete structured data
   - All collected inventory
   - All identified risks

## Next Steps

1. Review the generated HTML report
2. Focus on high-severity risks first
3. Investigate role-enabled groups
4. Review service principal ownerships
5. Audit PIM assignments
6. Check nested group memberships

## Getting Help

```powershell
# Get help for any function
Get-Help Invoke-ScEntraAnalysis -Detailed
Get-Help Get-ScEntraUsers -Examples
Get-Help Export-ScEntraReport -Full

# List all available functions
Get-Command -Module ScEntra
```

## Examples

See `Examples.ps1` for more detailed usage examples.
