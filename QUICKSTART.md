# ScEntra Quick Start Guide

## Installation

```powershell
# Clone the repository
git clone https://github.com/azurekid/ScEntra.git
cd ScEntra

# Import the module
Import-Module ./ScEntra.psd1
```

## Quick Analysis

### 1️⃣ Run Complete Analysis (Recommended)

```powershell
# This will:
# - Connect to Microsoft Graph
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
# Connect first with specific scopes
Connect-MgGraph -Scopes @(
    "User.Read.All"
    "Group.Read.All"
    "Application.Read.All"
    "RoleManagement.Read.Directory"
    "RoleEligibilitySchedule.Read.Directory"
    "RoleAssignmentSchedule.Read.Directory"
)

# Run analysis without re-authenticating
Invoke-ScEntraAnalysis -SkipConnection
```

## Common Scenarios

### Find Role-Enabled Groups

```powershell
Import-Module ./ScEntra.psd1

# Get all groups
$groups = Get-ScEntraGroups

# Filter to role-enabled groups
$roleEnabledGroups = $groups | Where-Object { $_.IsAssignableToRole -eq $true }

# Display
$roleEnabledGroups | Format-Table DisplayName, MemberCount, IsAssignableToRole
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
    $user = $users | Where-Object { $_.Id -eq $userRole.Name }
    Write-Host "$($user.DisplayName): $($userRole.Count) roles" -ForegroundColor Yellow
    $userRole.Group | ForEach-Object { Write-Host "  - $($_.RoleName)" }
}
```

### Analyze Service Principal Risks

```powershell
$sps = Get-ScEntraServicePrincipals
$roles = Get-ScEntraRoleAssignments

# Find service principals with role assignments
$spRoles = $roles | Where-Object { $_.MemberType -match 'servicePrincipal' }

foreach ($spRole in $spRoles) {
    $sp = $sps | Where-Object { $_.Id -eq $spRole.MemberId }
    if ($sp) {
        Write-Host "Service Principal: $($sp.DisplayName)" -ForegroundColor Cyan
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
$groups = Get-ScEntraGroups

# Check a specific group for nested members
$groupId = "your-group-id-here"

$directMembers = Get-MgGroupMember -GroupId $groupId -All
$transitiveMembers = Get-MgGroupTransitiveMember -GroupId $groupId -All

$nestedCount = $transitiveMembers.Count - $directMembers.Count

Write-Host "Direct Members: $($directMembers.Count)" -ForegroundColor Green
Write-Host "Nested Members: $nestedCount" -ForegroundColor Yellow
Write-Host "Total Members: $($transitiveMembers.Count)" -ForegroundColor Cyan
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

```powershell
# Disconnect and reconnect
Disconnect-MgGraph
Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "Application.Read.All"
```

### Missing Permissions

If you get permission errors, ensure your account has:
- Global Reader role (minimum)
- Or specific permissions: User.Read.All, Group.Read.All, Application.Read.All, RoleManagement.Read.Directory

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
