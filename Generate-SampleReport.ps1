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

# New-ScEntraGraphData is a private helper, so load it explicitly if it is not exported
if (-not (Get-Command -Name New-ScEntraGraphData -ErrorAction SilentlyContinue)) {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Private/New-ScEntraGraphData.ps1')
}

$graphAppId = "00000003-0000-0000-c000-000000000000"
$permissionIds = @{
    ApplicationReadWriteAll        = "18a4783c-866b-4cc7-a460-3d5e5662c884"
    DirectoryAccessAsUserAll       = "741f803b-c850-494e-b5df-cde7c675a1ca"
    RoleManagementReadWriteDirectory = "62a82d76-70ea-41e2-9197-370581804d09"
    DirectoryReadWriteAll          = "19dbc75e-c2e2-444c-a770-ec69d8559fc7"
}

# Create sample identities that cover every scenario/attack path
$sampleUsers = @(
    [PSCustomObject]@{
        Id = "user-global"
        DisplayName = "John Admin"
        UserPrincipalName = "john.admin@contoso.com"
        AccountEnabled = $true
        UserType = "Member"
        Mail = "john.admin@contoso.com"
        Department = "Digital Operations"
    }
    [PSCustomObject]@{
        Id = "user-appadmin"
        DisplayName = "Jane DevOps"
        UserPrincipalName = "jane.devops@contoso.com"
        AccountEnabled = $true
        UserType = "Member"
        Mail = "jane.devops@contoso.com"
        Department = "Cloud Platform"
    }
    [PSCustomObject]@{
        Id = "user-privrole"
        DisplayName = "Bob Privileged"
        UserPrincipalName = "bob.privileged@contoso.com"
        AccountEnabled = $true
        UserType = "Member"
        Mail = "bob.privileged@contoso.com"
        Department = "Identity"
    }
    [PSCustomObject]@{
        Id = "user-secops"
        DisplayName = "Priya SecOps"
        UserPrincipalName = "priya.secops@contoso.com"
        AccountEnabled = $true
        UserType = "Member"
        Mail = "priya.secops@contoso.com"
        Department = "Security Operations"
    }
    [PSCustomObject]@{
        Id = "user-identity"
        DisplayName = "Maya Identity"
        UserPrincipalName = "maya.identity@contoso.com"
        AccountEnabled = $true
        UserType = "Member"
        Mail = "maya.identity@contoso.com"
        Department = "IAM Engineering"
    }
    [PSCustomObject]@{
        Id = "user-contractor"
        DisplayName = "Alex Contractor"
        UserPrincipalName = "alex.contractor@contoso.com"
        AccountEnabled = $true
        UserType = "Guest"
        Mail = "alex.contractor@contoso.com"
        Department = "Automation"
    }
)

$sampleGroups = @(
    [PSCustomObject]@{
        Id = "group-breakglass"
        DisplayName = "Breakglass Global Admins"
        Description = "Role-enabled emergency access team"
        IsAssignableToRole = $true
        IsPIMEnabled = $true
        SecurityEnabled = $true
        MemberCount = 3
    }
    [PSCustomObject]@{
        Id = "group-ops"
        DisplayName = "Privileged Operations"
        Description = "Operations crew that activates PIM and owns automation"
        IsAssignableToRole = $true
        IsPIMEnabled = $false
        SecurityEnabled = $true
        MemberCount = 4
    }
    [PSCustomObject]@{
        Id = "group-analytics"
        DisplayName = "Security Analytics"
        Description = "Nested group feeding privileged roles"
        IsAssignableToRole = $false
        IsPIMEnabled = $false
        SecurityEnabled = $true
        MemberCount = 3
    }
)

$graphResourceSp = [PSCustomObject]@{
    Id = "sp-microsoft-graph"
    DisplayName = "Microsoft Graph"
    AppId = $graphAppId
    AccountEnabled = $true
    oauth2PermissionScopes = @(
        [PSCustomObject]@{
            Id = $permissionIds.DirectoryAccessAsUserAll
            Value = "Directory.AccessAsUser.All"
            AdminConsentDisplayName = "Access directory as the signed-in user"
            AdminConsentDescription = "Allows the app to have the same access as the signed-in user."
        }
    )
    appRoles = @(
        [PSCustomObject]@{
            Id = $permissionIds.ApplicationReadWriteAll
            Value = "Application.ReadWrite.All"
            DisplayName = "Read and write all applications"
            Description = "Allows the app to create, update, delete, and read applications."
        }
        [PSCustomObject]@{
            Id = $permissionIds.RoleManagementReadWriteDirectory
            Value = "RoleManagement.ReadWrite.Directory"
            DisplayName = "Manage directory roles"
            Description = "Allows the app to read and write directory role assignments."
        }
        [PSCustomObject]@{
            Id = $permissionIds.DirectoryReadWriteAll
            Value = "Directory.ReadWrite.All"
            DisplayName = "Read and write directory data"
            Description = "Allows the app to write data in your directory."
        }
    )
    GrantedApplicationPermissions = @()
    GrantedDelegatedPermissions = @()
}

$automationAppPerms = @(
    [PSCustomObject]@{
        AssignmentId = "grant-app-automation"
        ResourceId = $graphResourceSp.Id
        ResourceDisplayName = "Microsoft Graph"
        AppRoleId = $permissionIds.ApplicationReadWriteAll
        AppRoleValue = "Application.ReadWrite.All"
        AppRoleDisplayName = "Read and write all applications"
        AppRoleDescription = "Allows the runbook engine to manage app registrations."
    }
)
$automationDelegatedPerms = @(
    [PSCustomObject]@{
        GrantId = "grant-delegated-automation"
        ResourceId = $graphResourceSp.Id
        ResourceDisplayName = "Microsoft Graph"
        ConsentType = "AllPrincipals"
        PrincipalId = $null
        RawScope = $null
        ResolvedScopes = @(
            [PSCustomObject]@{
                ScopeId = $permissionIds.DirectoryAccessAsUserAll
                ScopeName = "Directory.AccessAsUser.All"
                ScopeDisplayName = "Access directory as the signed-in user"
                ScopeDescription = "Provides full delegated access mirroring privileged users."
            }
        )
    }
)

$devOpsAppPerms = @(
    [PSCustomObject]@{
        AssignmentId = "grant-app-devops"
        ResourceId = $graphResourceSp.Id
        ResourceDisplayName = "Microsoft Graph"
        AppRoleId = $permissionIds.RoleManagementReadWriteDirectory
        AppRoleValue = "RoleManagement.ReadWrite.Directory"
        AppRoleDisplayName = "Manage directory roles"
        AppRoleDescription = "Allows deployment pipelines to modify privileged assignments."
    }
)

$sampleServicePrincipals = @(
    [PSCustomObject]@{
        Id = "sp-automation"
        DisplayName = "Automation Runbook Engine"
        AppId = "11111111-1111-1111-1111-111111111111"
        AccountEnabled = $true
        GrantedApplicationPermissions = $automationAppPerms
        GrantedDelegatedPermissions = $automationDelegatedPerms
    }
    [PSCustomObject]@{
        Id = "sp-devops"
        DisplayName = "DevOps Build Agents"
        AppId = "22222222-2222-2222-2222-222222222222"
        AccountEnabled = $true
        GrantedApplicationPermissions = $devOpsAppPerms
        GrantedDelegatedPermissions = @()
    }
    $graphResourceSp
)

$sampleApps = @(
    [PSCustomObject]@{
        Id = "app-customer-portal"
        DisplayName = "Customer Success Portal"
        AppId = "33333333-3333-3333-3333-333333333333"
        ApiPermissions = @(
            [PSCustomObject]@{
                ResourceAppId = $graphAppId
                ResourceAccess = @(
                    [PSCustomObject]@{
                        Id = $permissionIds.ApplicationReadWriteAll
                        Type = "Role"
                    }
                    [PSCustomObject]@{
                        Id = $permissionIds.DirectoryAccessAsUserAll
                        Type = "Scope"
                    }
                )
            }
        )
    }
    [PSCustomObject]@{
        Id = "app-identity-gov"
        DisplayName = "Identity Governance Toolkit"
        AppId = "44444444-4444-4444-4444-444444444444"
        ApiPermissions = @(
            [PSCustomObject]@{
                ResourceAppId = $graphAppId
                ResourceAccess = @(
                    [PSCustomObject]@{
                        Id = $permissionIds.DirectoryReadWriteAll
                        Type = "Role"
                    }
                    [PSCustomObject]@{
                        Id = $permissionIds.RoleManagementReadWriteDirectory
                        Type = "Role"
                    }
                )
            }
        )
    }
)

$sampleRoleAssignments = @(
    [PSCustomObject]@{
        RoleId = "role-ga"
        RoleName = "Global Administrator"
        MemberId = "group-breakglass"
        MemberType = "group"
        AssignmentType = "Direct"
        RoleDescription = "Full admin access"
    }
    [PSCustomObject]@{
        RoleId = "role-secadmin"
        RoleName = "Security Administrator"
        MemberId = "user-global"
        MemberType = "user"
        AssignmentType = "Direct"
        RoleDescription = "Manage security configuration"
    }
    [PSCustomObject]@{
        RoleId = "role-pra"
        RoleName = "Privileged Role Administrator"
        MemberId = "user-privrole"
        MemberType = "user"
        AssignmentType = "Direct"
        RoleDescription = "Manage privileged role assignments"
    }
    [PSCustomObject]@{
        RoleId = "role-appadmin"
        RoleName = "Application Administrator"
        MemberId = "user-appadmin"
        MemberType = "user"
        AssignmentType = "Direct"
        RoleDescription = "Manage app registrations and SPNs"
    }
    [PSCustomObject]@{
        RoleId = "role-cloudapp"
        RoleName = "Cloud Application Administrator"
        MemberId = "group-ops"
        MemberType = "group"
        AssignmentType = "Direct"
        RoleDescription = "Manage cloud app resources"
    }
    [PSCustomObject]@{
        RoleId = "role-useradmin"
        RoleName = "User Administrator"
        MemberId = "sp-automation"
        MemberType = "servicePrincipal"
        AssignmentType = "Direct"
        RoleDescription = "Manage privileged users via automation"
    }
    [PSCustomObject]@{
        RoleId = "role-securityreader"
        RoleName = "Security Reader"
        MemberId = "group-analytics"
        MemberType = "group"
        AssignmentType = "Direct"
        RoleDescription = "Read security data"
    }
)

$samplePIMAssignments = @(
    [PSCustomObject]@{
        AssignmentId = "pim-ga"
        RoleId = "role-ga"
        RoleName = "Global Administrator"
        PrincipalId = "user-global"
        PrincipalType = "user"
        AssignmentType = "PIM-Eligible"
        Status = "Provisioned"
    }
    [PSCustomObject]@{
        AssignmentId = "pim-pra"
        RoleId = "role-pra"
        RoleName = "Privileged Role Administrator"
        PrincipalId = "user-global"
        PrincipalType = "user"
        AssignmentType = "PIM-Eligible"
        Status = "Provisioned"
    }
    [PSCustomObject]@{
        AssignmentId = "pim-appadmin"
        RoleId = "role-appadmin"
        RoleName = "Application Administrator"
        PrincipalId = "user-global"
        PrincipalType = "user"
        AssignmentType = "PIM-Eligible"
        Status = "Provisioned"
    }
    [PSCustomObject]@{
        AssignmentId = "pim-secadmin"
        RoleId = "role-secadmin"
        RoleName = "Security Administrator"
        PrincipalId = "user-global"
        PrincipalType = "user"
        AssignmentType = "PIM-Eligible"
        Status = "Provisioned"
    }
)

$groupMemberships = @{
    "group-breakglass" = @(
        [PSCustomObject]@{
            id = "user-global"
            displayName = "John Admin"
            userPrincipalName = "john.admin@contoso.com"
            '@odata.type' = '#microsoft.graph.user'
            isPIMEligible = $true
        }
        [PSCustomObject]@{
            id = "group-ops"
            displayName = "Privileged Operations"
            '@odata.type' = '#microsoft.graph.group'
        }
        [PSCustomObject]@{
            id = "user-identity"
            displayName = "Maya Identity"
            userPrincipalName = "maya.identity@contoso.com"
            '@odata.type' = '#microsoft.graph.user'
        }
    )
    "group-ops" = @(
        [PSCustomObject]@{
            id = "user-appadmin"
            displayName = "Jane DevOps"
            userPrincipalName = "jane.devops@contoso.com"
            '@odata.type' = '#microsoft.graph.user'
        }
        [PSCustomObject]@{
            id = "user-secops"
            displayName = "Priya SecOps"
            userPrincipalName = "priya.secops@contoso.com"
            '@odata.type' = '#microsoft.graph.user'
        }
        [PSCustomObject]@{
            id = "user-privrole"
            displayName = "Bob Privileged"
            userPrincipalName = "bob.privileged@contoso.com"
            '@odata.type' = '#microsoft.graph.user'
        }
        [PSCustomObject]@{
            id = "group-analytics"
            displayName = "Security Analytics"
            '@odata.type' = '#microsoft.graph.group'
        }
    )
    "group-analytics" = @(
        [PSCustomObject]@{
            id = "user-secops"
            displayName = "Priya SecOps"
            userPrincipalName = "priya.secops@contoso.com"
            '@odata.type' = '#microsoft.graph.user'
        }
        [PSCustomObject]@{
            id = "user-contractor"
            displayName = "Alex Contractor"
            userPrincipalName = "alex.contractor@contoso.com"
            '@odata.type' = '#microsoft.graph.user'
        }
        [PSCustomObject]@{
            id = "user-identity"
            displayName = "Maya Identity"
            userPrincipalName = "maya.identity@contoso.com"
            '@odata.type' = '#microsoft.graph.user'
        }
    )
}

$groupOwners = @{
    "group-breakglass" = @(
        [PSCustomObject]@{
            id = "user-identity"
            displayName = "Maya Identity"
            userPrincipalName = "maya.identity@contoso.com"
        }
        [PSCustomObject]@{
            id = "user-appadmin"
            displayName = "Jane DevOps"
            userPrincipalName = "jane.devops@contoso.com"
        }
    )
    "group-ops" = @(
        [PSCustomObject]@{
            id = "user-secops"
            displayName = "Priya SecOps"
            userPrincipalName = "priya.secops@contoso.com"
        }
    )
}

$spOwners = @{
    "sp-automation" = @(
        [PSCustomObject]@{
            id = "user-appadmin"
            displayName = "Jane DevOps"
            userPrincipalName = "jane.devops@contoso.com"
        }
        [PSCustomObject]@{
            id = "user-contractor"
            displayName = "Alex Contractor"
            userPrincipalName = "alex.contractor@contoso.com"
        }
    )
    "sp-devops" = @(
        [PSCustomObject]@{
            id = "user-privrole"
            displayName = "Bob Privileged"
            userPrincipalName = "bob.privileged@contoso.com"
        }
    )
}

$spAppRoleAssignments = @{
    "sp-automation" = @(
        [PSCustomObject]@{
            principalId = "user-secops"
            principalDisplayName = "Priya SecOps"
            principalType = "User"
        }
    )
    "sp-devops" = @(
        [PSCustomObject]@{
            principalId = "group-ops"
            principalDisplayName = "Privileged Operations"
            principalType = "Group"
        }
    )
}

$appOwners = @{
    "app-customer-portal" = @(
        [PSCustomObject]@{
            id = "user-secops"
            displayName = "Priya SecOps"
            userPrincipalName = "priya.secops@contoso.com"
        }
        [PSCustomObject]@{
            id = "user-appadmin"
            displayName = "Jane DevOps"
            userPrincipalName = "jane.devops@contoso.com"
        }
    )
    "app-identity-gov" = @(
        [PSCustomObject]@{
            id = "user-global"
            displayName = "John Admin"
            userPrincipalName = "john.admin@contoso.com"
        }
        [PSCustomObject]@{
            id = "user-appadmin"
            displayName = "Jane DevOps"
            userPrincipalName = "jane.devops@contoso.com"
        }
        [PSCustomObject]@{
            id = "user-privrole"
            displayName = "Bob Privileged"
            userPrincipalName = "bob.privileged@contoso.com"
        }
        [PSCustomObject]@{
            id = "user-secops"
            displayName = "Priya SecOps"
            userPrincipalName = "priya.secops@contoso.com"
        }
        [PSCustomObject]@{
            id = "user-identity"
            displayName = "Maya Identity"
            userPrincipalName = "maya.identity@contoso.com"
        }
        [PSCustomObject]@{
            id = "user-contractor"
            displayName = "Alex Contractor"
            userPrincipalName = "alex.contractor@contoso.com"
        }
    )
}

$sampleEscalationRisks = @(
    [PSCustomObject]@{
        RiskType = "RoleEnabledGroup"
        Severity = "High"
        GroupId = "group-breakglass"
        GroupName = "Breakglass Global Admins"
        RoleName = "Global Administrator"
        MemberCount = 3
        OwnerCount = 2
        Description = "Role-enabled group 'Breakglass Global Admins' holds 'Global Administrator' with 3 members and 2 owners capable of escalation."
    }
    [PSCustomObject]@{
        RiskType = "NestedGroupMembership"
        Severity = "Medium"
        GroupId = "group-ops"
        GroupName = "Privileged Operations"
        RoleName = "Cloud Application Administrator"
        DirectMembers = 3
        NestedMembers = 1
        Description = "Group 'Privileged Operations' inherits access from a nested group while holding 'Cloud Application Administrator'."
    }
    [PSCustomObject]@{
        RiskType = "ServicePrincipalOwnership"
        Severity = "High"
        ServicePrincipalId = "sp-automation"
        ServicePrincipalName = "Automation Runbook Engine"
        RoleName = "User Administrator"
        OwnerCount = 2
        Description = "Service Principal 'Automation Runbook Engine' with 'User Administrator' has multiple owners who can abuse automation credentials."
    }
    [PSCustomObject]@{
        RiskType = "AppRegistrationOwnership"
        Severity = "Medium"
        AppId = "app-identity-gov"
        AppName = "Identity Governance Toolkit"
        OwnerCount = 6
        Description = "App Registration 'Identity Governance Toolkit' has six owners, increasing the likelihood of credential leakage."
    }
    [PSCustomObject]@{
        RiskType = "AppAdministratorEscalation"
        Severity = "High"
        PrincipalId = "user-appadmin"
        PrincipalType = "user"
        RoleName = "Application Administrator"
        PrivilegedSPCount = 2
        IsPIM = $false
        Description = "Application Administrator Jane DevOps can manage two service principals with privileged roles, enabling indirect escalation."
    }
    [PSCustomObject]@{
        RiskType = "RoleAdministratorEscalation"
        Severity = "Critical"
        PrincipalId = "user-privrole"
        PrincipalType = "user"
        RoleName = "Privileged Role Administrator"
        IsPIM = $false
        Description = "Privileged Role Administrator Bob Privileged can assign Global Administrator on demand."
    }
    [PSCustomObject]@{
        RiskType = "MultiplePIMRoles"
        Severity = "Medium"
        PrincipalId = "user-global"
        PIMRoleCount = 4
        Roles = "Global Administrator, Privileged Role Administrator, Application Administrator, Security Administrator"
        Description = "Principal John Admin has four concurrent PIM role eligibilities, concentrating privileged access."
    }
)

# Build detailed graph data so the report renders every attack path
$graphData = New-ScEntraGraphData `
    -Users $sampleUsers `
    -Groups $sampleGroups `
    -ServicePrincipals $sampleServicePrincipals `
    -AppRegistrations $sampleApps `
    -RoleAssignments $sampleRoleAssignments `
    -PIMAssignments $samplePIMAssignments `
    -GroupMemberships $groupMemberships `
    -GroupOwners $groupOwners `
    -SPOwners $spOwners `
    -SPAppRoleAssignments $spAppRoleAssignments `
    -AppOwners $appOwners

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
    -GraphData $graphData `
    -OutputPath "./ScEntra-Sample-Report.html"

Write-Host "`n✓ Sample report generated: ScEntra-Sample-Report.html" -ForegroundColor Green
Write-Host "Open it in a web browser to see the visualization" -ForegroundColor Cyan
