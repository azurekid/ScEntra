#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Generate a sample report with mock data to demonstrate visualization

.DESCRIPTION
    Creates a sample HTML report without needing to connect to Entra ID
#>

Write-Host "Generating Sample Report..." -ForegroundColor Cyan

# Import module
Import-Module ./ScEntra.psd1 -Force

# Create sample data
$sampleUsers = @(
    [PSCustomObject]@{
        Id = "user1"
        DisplayName = "John Admin"
        UserPrincipalName = "john.admin@contoso.com"
        AccountEnabled = $true
        UserType = "Member"
        Mail = "john.admin@contoso.com"
    }
    [PSCustomObject]@{
        Id = "user2"
        DisplayName = "Jane User"
        UserPrincipalName = "jane.user@contoso.com"
        AccountEnabled = $true
        UserType = "Member"
        Mail = "jane.user@contoso.com"
    }
    [PSCustomObject]@{
        Id = "user3"
        DisplayName = "Bob Manager"
        UserPrincipalName = "bob.manager@contoso.com"
        AccountEnabled = $true
        UserType = "Member"
        Mail = "bob.manager@contoso.com"
    }
)

$sampleGroups = @(
    [PSCustomObject]@{
        Id = "group1"
        DisplayName = "Global Administrators"
        IsAssignableToRole = $true
        SecurityEnabled = $true
        MemberCount = 5
        Description = "Global admin group"
    }
    [PSCustomObject]@{
        Id = "group2"
        DisplayName = "Security Readers"
        IsAssignableToRole = $true
        SecurityEnabled = $true
        MemberCount = 12
        Description = "Security reader group"
    }
    [PSCustomObject]@{
        Id = "group3"
        DisplayName = "All Employees"
        IsAssignableToRole = $false
        SecurityEnabled = $true
        MemberCount = 150
        Description = "All company employees"
    }
)

$sampleServicePrincipals = @(
    [PSCustomObject]@{
        Id = "sp1"
        DisplayName = "Azure DevOps"
        AppId = "app-guid-1"
        AccountEnabled = $true
    }
    [PSCustomObject]@{
        Id = "sp2"
        DisplayName = "Automation Account"
        AppId = "app-guid-2"
        AccountEnabled = $true
    }
)

$sampleApps = @(
    [PSCustomObject]@{
        Id = "app1"
        DisplayName = "Custom App 1"
        AppId = "custom-app-1"
    }
    [PSCustomObject]@{
        Id = "app2"
        DisplayName = "Custom App 2"
        AppId = "custom-app-2"
    }
)

$sampleRoleAssignments = @(
    [PSCustomObject]@{
        RoleId = "role1"
        RoleName = "Global Administrator"
        MemberId = "user1"
        MemberType = "user"
        AssignmentType = "Direct"
        RoleDescription = "Full admin access"
    }
    [PSCustomObject]@{
        RoleId = "role2"
        RoleName = "Security Administrator"
        MemberId = "group1"
        MemberType = "group"
        AssignmentType = "Direct"
        RoleDescription = "Security admin access"
    }
    [PSCustomObject]@{
        RoleId = "role3"
        RoleName = "Application Administrator"
        MemberId = "user2"
        MemberType = "user"
        AssignmentType = "Direct"
        RoleDescription = "App admin access"
    }
    [PSCustomObject]@{
        RoleId = "role4"
        RoleName = "User Administrator"
        MemberId = "user3"
        MemberType = "user"
        AssignmentType = "Direct"
        RoleDescription = "User admin access"
    }
)

$samplePIMAssignments = @(
    [PSCustomObject]@{
        AssignmentId = "pim1"
        RoleId = "role1"
        RoleName = "Global Administrator"
        PrincipalId = "user1"
        PrincipalType = "user"
        AssignmentType = "PIM-Eligible"
        Status = "Provisioned"
    }
    [PSCustomObject]@{
        AssignmentId = "pim2"
        RoleId = "role2"
        RoleName = "Security Administrator"
        PrincipalId = "user2"
        PrincipalType = "user"
        AssignmentType = "PIM-Active"
        Status = "Provisioned"
    }
)

$sampleEscalationRisks = @(
    [PSCustomObject]@{
        RiskType = "RoleEnabledGroup"
        Severity = "High"
        GroupId = "group1"
        GroupName = "Global Administrators"
        RoleName = "Global Administrator"
        MemberCount = 5
        OwnerCount = 2
        Description = "Role-enabled group 'Global Administrators' has 'Global Administrator' role with 5 members"
    }
    [PSCustomObject]@{
        RiskType = "NestedGroupMembership"
        Severity = "Medium"
        GroupId = "group2"
        GroupName = "Security Readers"
        RoleName = "Security Reader"
        DirectMembers = 8
        NestedMembers = 4
        Description = "Group 'Security Readers' with 'Security Reader' has 4 members through nested groups"
    }
    [PSCustomObject]@{
        RiskType = "ServicePrincipalOwnership"
        Severity = "High"
        ServicePrincipalId = "sp1"
        ServicePrincipalName = "Azure DevOps"
        RoleName = "Application Administrator"
        OwnerCount = 3
        Description = "Service Principal 'Azure DevOps' with 'Application Administrator' has 3 owners who could potentially abuse permissions"
    }
    [PSCustomObject]@{
        RiskType = "MultiplePIMRoles"
        Severity = "Medium"
        PrincipalId = "user1"
        PIMRoleCount = 3
        Roles = "Global Administrator, Security Administrator, User Administrator"
        Description = "Principal has 3 PIM role assignments: Global Administrator, Security Administrator, User Administrator..."
    }
)

# Generate report
Write-Host "Calling Export-ScEntraReport..." -ForegroundColor Yellow

Export-ScEntraReport `
    -Users $sampleUsers `
    -Groups $sampleGroups `
    -ServicePrincipals $sampleServicePrincipals `
    -AppRegistrations $sampleApps `
    -RoleAssignments $sampleRoleAssignments `
    -PIMAssignments $samplePIMAssignments `
    -EscalationRisks $sampleEscalationRisks `
    -OutputPath "./ScEntra-Sample-Report.html"

Write-Host "`n✓ Sample report generated: ScEntra-Sample-Report.html" -ForegroundColor Green
Write-Host "Open it in a web browser to see the visualization" -ForegroundColor Cyan
