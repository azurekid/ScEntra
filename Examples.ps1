#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Example script demonstrating ScEntra usage

.DESCRIPTION
    This script shows various ways to use the ScEntra module for
    Entra ID security analysis and escalation path detection.

.EXAMPLE
    ./Examples.ps1
#>

# Import the ScEntra module
Write-Host "Importing ScEntra module..." -ForegroundColor Cyan
Import-Module ./ScEntra.psd1 -Force

# Example 1: Simple analysis with automatic connection
Write-Host "`n=== Example 1: Simple Analysis ===" -ForegroundColor Green
Write-Host "This will perform a complete analysis and generate a report" -ForegroundColor Yellow
# Uncomment to run:
# Invoke-ScEntraAnalysis

# Example 2: Manual connection with specific scopes
Write-Host "`n=== Example 2: Manual Connection ===" -ForegroundColor Green
Write-Host "Connect to Graph with specific scopes first" -ForegroundColor Yellow

<#
Connect-MgGraph -Scopes @(
    "User.Read.All"
    "Group.Read.All"
    "Application.Read.All"
    "RoleManagement.Read.Directory"
    "RoleEligibilitySchedule.Read.Directory"
    "RoleAssignmentSchedule.Read.Directory"
)

Invoke-ScEntraAnalysis -SkipConnection -OutputPath "./my-custom-report.html"
#>

# Example 3: Using individual functions
Write-Host "`n=== Example 3: Individual Functions ===" -ForegroundColor Green
Write-Host "Use specific functions for targeted analysis" -ForegroundColor Yellow

<#
# Get users
Write-Host "Getting users..." -ForegroundColor Cyan
$users = Get-ScEntraUsers
Write-Host "Found $($users.Count) users" -ForegroundColor Green

# Get groups
Write-Host "Getting groups..." -ForegroundColor Cyan
$groups = Get-ScEntraGroups
Write-Host "Found $($groups.Count) groups" -ForegroundColor Green

# Get role assignments
Write-Host "Getting role assignments..." -ForegroundColor Cyan
$roleAssignments = Get-ScEntraRoleAssignments
Write-Host "Found $($roleAssignments.Count) role assignments" -ForegroundColor Green

# Analyze specific users
$adminUsers = $users | Where-Object { $_.UserPrincipalName -like "*admin*" }
Write-Host "Found $($adminUsers.Count) admin-like users" -ForegroundColor Yellow
#>

# Example 4: Custom analysis and filtering
Write-Host "`n=== Example 4: Custom Analysis ===" -ForegroundColor Green
Write-Host "Perform custom filtering and analysis" -ForegroundColor Yellow

<#
# Get all data
$users = Get-ScEntraUsers
$groups = Get-ScEntraGroups
$servicePrincipals = Get-ScEntraServicePrincipals
$apps = Get-ScEntraAppRegistrations
$roles = Get-ScEntraRoleAssignments
$pim = Get-ScEntraPIMAssignments

# Find role-enabled groups
$roleEnabledGroups = $groups | Where-Object { $_.IsAssignableToRole -eq $true }
Write-Host "Role-enabled groups: $($roleEnabledGroups.Count)" -ForegroundColor Yellow

foreach ($group in $roleEnabledGroups) {
    Write-Host "  - $($group.DisplayName)" -ForegroundColor White
}

# Find users with multiple roles
$userRoles = $roles | Where-Object { $_.MemberType -eq 'user' } | Group-Object -Property MemberId
$multiRoleUsers = $userRoles | Where-Object { $_.Count -gt 1 }

Write-Host "`nUsers with multiple roles: $($multiRoleUsers.Count)" -ForegroundColor Yellow

foreach ($userRole in $multiRoleUsers) {
    $user = $users | Where-Object { $_.Id -eq $userRole.Name }
    if ($user) {
        Write-Host "  - $($user.DisplayName): $($userRole.Count) roles" -ForegroundColor White
    }
}
#>

# Example 5: Export to custom formats
Write-Host "`n=== Example 5: Custom Export ===" -ForegroundColor Green
Write-Host "Export data in different formats" -ForegroundColor Yellow

<#
# Run analysis
$results = Invoke-ScEntraAnalysis -SkipConnection

# Export high-risk items to CSV
$highRisks = $results.EscalationRisks | Where-Object { $_.Severity -eq 'High' }
$highRisks | Export-Csv -Path "./high-risks.csv" -NoTypeInformation
Write-Host "Exported $($highRisks.Count) high-risk items to high-risks.csv" -ForegroundColor Green

# Export all groups to JSON
$results.Groups | ConvertTo-Json -Depth 10 | Out-File "./groups.json"
Write-Host "Exported groups to groups.json" -ForegroundColor Green

# Export role assignments to CSV
$results.RoleAssignments | Export-Csv -Path "./role-assignments.csv" -NoTypeInformation
Write-Host "Exported role assignments to role-assignments.csv" -ForegroundColor Green
#>

# Example 6: Focused escalation analysis
Write-Host "`n=== Example 6: Focused Escalation Analysis ===" -ForegroundColor Green
Write-Host "Analyze specific escalation scenarios" -ForegroundColor Yellow

<#
# Get data
$users = Get-ScEntraUsers
$groups = Get-ScEntraGroups
$sps = Get-ScEntraServicePrincipals
$apps = Get-ScEntraAppRegistrations
$roles = Get-ScEntraRoleAssignments
$pim = Get-ScEntraPIMAssignments

# Run escalation analysis
$risks = Get-ScEntraEscalationPaths `
    -Users $users `
    -Groups $groups `
    -RoleAssignments $roles `
    -PIMAssignments $pim `
    -ServicePrincipals $sps `
    -AppRegistrations $apps

# Group by risk type
$risksByType = $risks | Group-Object -Property RiskType

foreach ($riskGroup in $risksByType) {
    Write-Host "`n$($riskGroup.Name): $($riskGroup.Count) risks" -ForegroundColor Cyan
    
    foreach ($risk in $riskGroup.Group | Select-Object -First 3) {
        Write-Host "  [$($risk.Severity)] $($risk.Description)" -ForegroundColor White
    }
    
    if ($riskGroup.Count -gt 3) {
        Write-Host "  ... and $($riskGroup.Count - 3) more" -ForegroundColor Gray
    }
}
#>

Write-Host "`n=== Examples Complete ===" -ForegroundColor Green
Write-Host "Uncomment the examples you want to run and execute the script again" -ForegroundColor Yellow
Write-Host "`nFor a quick start, run:" -ForegroundColor Cyan
Write-Host "  Invoke-ScEntraAnalysis" -ForegroundColor White
