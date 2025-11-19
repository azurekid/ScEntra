#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to generate a sample report with graph visualization using mock data

.DESCRIPTION
    This script creates mock data to demonstrate the graph visualization feature
    without requiring actual Microsoft Graph API access.
#>

Import-Module ./ScEntra.psd1 -Force

Write-Host "Creating mock data for graph visualization test..." -ForegroundColor Cyan

# Mock Users
$users = @(
    [PSCustomObject]@{ id = "user1"; displayName = "Alice Admin"; userPrincipalName = "alice@contoso.com"; accountEnabled = $true; userType = "Member" }
    [PSCustomObject]@{ id = "user2"; displayName = "Bob Owner"; userPrincipalName = "bob@contoso.com"; accountEnabled = $true; userType = "Member" }
    [PSCustomObject]@{ id = "user3"; displayName = "Carol User"; userPrincipalName = "carol@contoso.com"; accountEnabled = $true; userType = "Member" }
    [PSCustomObject]@{ id = "user4"; displayName = "Dave Developer"; userPrincipalName = "dave@contoso.com"; accountEnabled = $true; userType = "Member" }
)

# Mock Groups  
$groups = @(
    [PSCustomObject]@{ id = "group1"; displayName = "Global Administrators"; isAssignableToRole = $true; securityEnabled = $true; memberCount = 2 }
    [PSCustomObject]@{ id = "group2"; displayName = "IT Admins"; isAssignableToRole = $false; securityEnabled = $true; memberCount = 3 }
    [PSCustomObject]@{ id = "group3"; displayName = "App Owners"; isAssignableToRole = $false; securityEnabled = $true; memberCount = 2 }
)

# Mock Service Principals
$servicePrincipals = @(
    [PSCustomObject]@{ id = "sp1"; displayName = "Production App"; appId = "app-guid-1"; accountEnabled = $true }
    [PSCustomObject]@{ id = "sp2"; displayName = "Automation Service"; appId = "app-guid-2"; accountEnabled = $true }
)

# Mock App Registrations
$appRegistrations = @(
    [PSCustomObject]@{ id = "app1"; displayName = "Production App"; appId = "app-guid-1" }
    [PSCustomObject]@{ id = "app2"; displayName = "Automation Service"; appId = "app-guid-2" }
)

# Mock Role Assignments
$roleAssignments = @(
    [PSCustomObject]@{ RoleId = "role1"; RoleName = "Global Administrator"; RoleDescription = "Full admin"; MemberId = "group1"; MemberType = "group"; AssignmentType = "Direct" }
    [PSCustomObject]@{ RoleId = "role2"; RoleName = "Application Administrator"; RoleDescription = "Manage apps"; MemberId = "user1"; MemberType = "user"; AssignmentType = "Direct" }
    [PSCustomObject]@{ RoleId = "role3"; RoleName = "Privileged Role Administrator"; RoleDescription = "Manage roles"; MemberId = "sp1"; MemberType = "servicePrincipal"; AssignmentType = "Direct" }
)

# Mock PIM Assignments
$pimAssignments = @(
    [PSCustomObject]@{ AssignmentId = "pim1"; RoleId = "role1"; RoleName = "Global Administrator"; PrincipalId = "user2"; PrincipalType = "user"; AssignmentType = "PIM-Eligible"; Status = "Provisioned" }
    [PSCustomObject]@{ AssignmentId = "pim2"; RoleId = "role2"; RoleName = "Application Administrator"; PrincipalId = "group2"; PrincipalType = "group"; AssignmentType = "PIM-Eligible"; Status = "Provisioned" }
)

# Mock Escalation Risks
$escalationRisks = @(
    [PSCustomObject]@{ RiskType = "RoleEnabledGroup"; Severity = "High"; GroupId = "group1"; GroupName = "Global Administrators"; RoleName = "Global Administrator"; MemberCount = 2; OwnerCount = 1; Description = "Role-enabled group 'Global Administrators' has 'Global Administrator' role with 2 members" }
    [PSCustomObject]@{ RiskType = "ServicePrincipalOwnership"; Severity = "High"; ServicePrincipalId = "sp1"; ServicePrincipalName = "Production App"; RoleName = "Privileged Role Administrator"; OwnerCount = 2; Description = "Service Principal 'Production App' with 'Privileged Role Administrator' has 2 owners who could potentially abuse permissions" }
    [PSCustomObject]@{ RiskType = "MultiplePIMRoles"; Severity = "Medium"; PrincipalId = "user1"; PIMRoleCount = 2; Roles = "Global Administrator, Application Administrator"; Description = "Principal has 2 PIM role assignments" }
)

# Mock Graph Data
$groupMemberships = @{
    "group1" = @(
        [PSCustomObject]@{ id = "user1"; displayName = "Alice Admin"; "@odata.type" = "#microsoft.graph.user" }
        [PSCustomObject]@{ id = "user2"; displayName = "Bob Owner"; "@odata.type" = "#microsoft.graph.user" }
    )
    "group2" = @(
        [PSCustomObject]@{ id = "user3"; displayName = "Carol User"; "@odata.type" = "#microsoft.graph.user" }
        [PSCustomObject]@{ id = "user4"; displayName = "Dave Developer"; "@odata.type" = "#microsoft.graph.user" }
        [PSCustomObject]@{ id = "group1"; displayName = "Global Administrators"; "@odata.type" = "#microsoft.graph.group" }
    )
    "group3" = @(
        [PSCustomObject]@{ id = "user2"; displayName = "Bob Owner"; "@odata.type" = "#microsoft.graph.user" }
    )
}

$groupOwners = @{
    "group1" = @([PSCustomObject]@{ id = "user1"; displayName = "Alice Admin" })
    "group3" = @([PSCustomObject]@{ id = "user2"; displayName = "Bob Owner" })
}

$spOwners = @{
    "sp1" = @(
        [PSCustomObject]@{ id = "user2"; displayName = "Bob Owner" }
        [PSCustomObject]@{ id = "user1"; displayName = "Alice Admin" }
    )
}

$spAppRoleAssignments = @{
    "sp1" = @(
        [PSCustomObject]@{ principalId = "user3"; principalDisplayName = "Carol User"; principalType = "User" }
        [PSCustomObject]@{ principalId = "group2"; principalDisplayName = "IT Admins"; principalType = "Group" }
    )
}

$appOwners = @{
    "app1" = @([PSCustomObject]@{ id = "user2"; displayName = "Bob Owner" })
    "app2" = @([PSCustomObject]@{ id = "user1"; displayName = "Alice Admin" })
}

Write-Host "Building mock escalation result with graph data..." -ForegroundColor Cyan

# Build graph data directly (simulating what Get-ScEntraEscalationPaths does)
$nodes = [System.Collections.ArrayList]::new()
$edges = [System.Collections.ArrayList]::new()

# Add role nodes
foreach ($role in ($roleAssignments + $pimAssignments | Select-Object -ExpandProperty RoleName -Unique)) {
    $null = $nodes.Add(@{ id = "role-$role"; label = $role; type = "role"; isPrivileged = $true })
}

# Add user nodes and edges
foreach ($user in $users) {
    $null = $nodes.Add(@{ id = $user.id; label = $user.displayName; type = "user"; userPrincipalName = $user.userPrincipalName; accountEnabled = $user.accountEnabled })
}

# Add group nodes
foreach ($group in $groups) {
    $null = $nodes.Add(@{ id = $group.id; label = $group.displayName; type = "group"; isAssignableToRole = $group.isAssignableToRole; securityEnabled = $group.securityEnabled })
}

# Add SP nodes
foreach ($sp in $servicePrincipals) {
    $null = $nodes.Add(@{ id = $sp.id; label = $sp.displayName; type = "servicePrincipal"; appId = $sp.appId; accountEnabled = $sp.accountEnabled })
}

# Add App nodes
foreach ($app in $appRegistrations) {
    $null = $nodes.Add(@{ id = $app.id; label = $app.displayName; type = "application"; appId = $app.appId })
}

# Add role assignment edges
foreach ($assignment in $roleAssignments) {
    $null = $edges.Add(@{ from = $assignment.MemberId; to = "role-$($assignment.RoleName)"; type = "has_role"; label = "Direct" })
}

# Add PIM edges
foreach ($pim in $pimAssignments) {
    $label = if ($pim.AssignmentType -eq 'PIM-Eligible') { 'Eligible' } else { 'PIM Active' }
    $null = $edges.Add(@{ from = $pim.PrincipalId; to = "role-$($pim.RoleName)"; type = "has_role"; label = $label; isPIM = $true })
}

# Add membership edges
foreach ($groupId in $groupMemberships.Keys) {
    foreach ($member in $groupMemberships[$groupId]) {
        $null = $edges.Add(@{ from = $member.id; to = $groupId; type = "member_of"; label = "Member" })
    }
}

# Add ownership edges
foreach ($groupId in $groupOwners.Keys) {
    foreach ($owner in $groupOwners[$groupId]) {
        $null = $edges.Add(@{ from = $owner.id; to = $groupId; type = "owns"; label = "Owner" })
    }
}

foreach ($spId in $spOwners.Keys) {
    foreach ($owner in $spOwners[$spId]) {
        $null = $edges.Add(@{ from = $owner.id; to = $spId; type = "owns"; label = "Owner" })
    }
}

foreach ($appId in $appOwners.Keys) {
    foreach ($owner in $appOwners[$appId]) {
        $null = $edges.Add(@{ from = $owner.id; to = $appId; type = "owns"; label = "Owner" })
    }
}

# Add SP app role assignment edges
foreach ($spId in $spAppRoleAssignments.Keys) {
    foreach ($assignment in $spAppRoleAssignments[$spId]) {
        $null = $edges.Add(@{ from = $assignment.principalId; to = $spId; type = "assigned_to"; label = "Assigned" })
    }
}

# Link apps to SPs
foreach ($app in $appRegistrations) {
    $sp = $servicePrincipals | Where-Object { $_.appId -eq $app.appId }
    if ($sp) {
        $null = $edges.Add(@{ from = $app.id; to = $sp.id; type = "has_service_principal"; label = "Creates" })
    }
}

$graphData = @{
    nodes = $nodes
    edges = $edges
}

Write-Host "Graph built with $($graphData.nodes.Count) nodes and $($graphData.edges.Count) edges" -ForegroundColor Green

Write-Host "`nGenerating report with graph visualization..." -ForegroundColor Cyan
$reportPath = Export-ScEntraReport `
    -Users $users `
    -Groups $groups `
    -ServicePrincipals $servicePrincipals `
    -AppRegistrations $appRegistrations `
    -RoleAssignments $roleAssignments `
    -PIMAssignments $pimAssignments `
    -EscalationRisks $escalationRisks `
    -GraphData $graphData `
    -OutputPath "./ScEntra-GraphTest-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"

Write-Host "`n✓ Test completed successfully!" -ForegroundColor Green
Write-Host "Report with graph visualization: $reportPath" -ForegroundColor Cyan
Write-Host "`nOpen the HTML file in a web browser to see the interactive graph visualization." -ForegroundColor Yellow
