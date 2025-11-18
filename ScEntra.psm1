#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Applications, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.Governance

<#
.SYNOPSIS
    ScEntra - Scan Entra for risk in role assignments and escalation paths

.DESCRIPTION
    This module provides functions to inventory Entra ID objects (users, groups, service principals, app registrations)
    and analyze privilege escalation risks through role assignments, PIM, and nested group memberships.
#>

#region Helper Functions

function Test-GraphConnection {
    <#
    .SYNOPSIS
        Tests if connected to Microsoft Graph
    #>
    try {
        $context = Get-MgContext
        if ($null -eq $context) {
            Write-Warning "Not connected to Microsoft Graph. Please run Connect-MgGraph first."
            return $false
        }
        return $true
    }
    catch {
        Write-Warning "Error checking Graph connection: $_"
        return $false
    }
}

function Get-AllGraphItems {
    <#
    .SYNOPSIS
        Helper function to get all items from Graph API with pagination
    #>
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )
    
    $allItems = @()
    $result = & $Command
    
    if ($result) {
        $allItems += $result
        
        # Handle pagination if available
        while ($result.PSObject.Properties['@odata.nextLink']) {
            $result = Invoke-MgGraphRequest -Uri $result.PSObject.Properties['@odata.nextLink'].Value -Method GET
            $allItems += $result.value
        }
    }
    
    return $allItems
}

#endregion

#region Inventory Functions

function Get-ScEntraUsers {
    <#
    .SYNOPSIS
        Gets all users from Entra ID
    
    .DESCRIPTION
        Retrieves comprehensive information about all users in the Entra ID tenant
    
    .EXAMPLE
        $users = Get-ScEntraUsers
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Test-GraphConnection)) {
        return
    }
    
    Write-Verbose "Retrieving all users from Entra ID..."
    
    try {
        $users = Get-AllGraphItems -Command {
            Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Mail, AccountEnabled, CreatedDateTime, UserType, OnPremisesSyncEnabled
        }
        
        Write-Host "Retrieved $($users.Count) users" -ForegroundColor Green
        return $users
    }
    catch {
        Write-Error "Error retrieving users: $_"
        return @()
    }
}

function Get-ScEntraGroups {
    <#
    .SYNOPSIS
        Gets all groups from Entra ID
    
    .DESCRIPTION
        Retrieves comprehensive information about all groups including role-enabled status
    
    .EXAMPLE
        $groups = Get-ScEntraGroups
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Test-GraphConnection)) {
        return
    }
    
    Write-Verbose "Retrieving all groups from Entra ID..."
    
    try {
        $groups = Get-AllGraphItems -Command {
            Get-MgGroup -All -Property Id, DisplayName, Description, GroupTypes, SecurityEnabled, MailEnabled, IsAssignableToRole, CreatedDateTime, MembershipRule, MembershipRuleProcessingState
        }
        
        Write-Host "Retrieved $($groups.Count) groups" -ForegroundColor Green
        
        # Add member count to each group
        foreach ($group in $groups) {
            try {
                $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
                $group | Add-Member -NotePropertyName MemberCount -NotePropertyValue $members.Count -Force
            }
            catch {
                $group | Add-Member -NotePropertyName MemberCount -NotePropertyValue 0 -Force
            }
        }
        
        return $groups
    }
    catch {
        Write-Error "Error retrieving groups: $_"
        return @()
    }
}

function Get-ScEntraServicePrincipals {
    <#
    .SYNOPSIS
        Gets all service principals from Entra ID
    
    .DESCRIPTION
        Retrieves comprehensive information about all service principals
    
    .EXAMPLE
        $servicePrincipals = Get-ScEntraServicePrincipals
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Test-GraphConnection)) {
        return
    }
    
    Write-Verbose "Retrieving all service principals from Entra ID..."
    
    try {
        $servicePrincipals = Get-AllGraphItems -Command {
            Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, ServicePrincipalType, AccountEnabled, CreatedDateTime, AppOwnerOrganizationId
        }
        
        Write-Host "Retrieved $($servicePrincipals.Count) service principals" -ForegroundColor Green
        return $servicePrincipals
    }
    catch {
        Write-Error "Error retrieving service principals: $_"
        return @()
    }
}

function Get-ScEntraAppRegistrations {
    <#
    .SYNOPSIS
        Gets all app registrations from Entra ID
    
    .DESCRIPTION
        Retrieves comprehensive information about all application registrations
    
    .EXAMPLE
        $apps = Get-ScEntraAppRegistrations
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Test-GraphConnection)) {
        return
    }
    
    Write-Verbose "Retrieving all app registrations from Entra ID..."
    
    try {
        $apps = Get-AllGraphItems -Command {
            Get-MgApplication -All -Property Id, DisplayName, AppId, CreatedDateTime, SignInAudience, PublisherDomain
        }
        
        Write-Host "Retrieved $($apps.Count) app registrations" -ForegroundColor Green
        return $apps
    }
    catch {
        Write-Error "Error retrieving app registrations: $_"
        return @()
    }
}

#endregion

#region Role Assignment Functions

function Get-ScEntraRoleAssignments {
    <#
    .SYNOPSIS
        Gets all directory role assignments
    
    .DESCRIPTION
        Retrieves all direct role assignments in Entra ID
    
    .EXAMPLE
        $roleAssignments = Get-ScEntraRoleAssignments
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Test-GraphConnection)) {
        return
    }
    
    Write-Verbose "Retrieving directory role assignments..."
    
    try {
        # Get all directory roles
        $roles = Get-MgDirectoryRole -All
        
        $allAssignments = @()
        
        foreach ($role in $roles) {
            Write-Verbose "Processing role: $($role.DisplayName)"
            
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
            
            foreach ($member in $members) {
                $assignment = [PSCustomObject]@{
                    RoleId = $role.Id
                    RoleName = $role.DisplayName
                    RoleDescription = $role.Description
                    MemberId = $member.Id
                    MemberType = $member.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', ''
                    AssignmentType = 'Direct'
                }
                $allAssignments += $assignment
            }
        }
        
        Write-Host "Retrieved $($allAssignments.Count) direct role assignments across $($roles.Count) roles" -ForegroundColor Green
        return $allAssignments
    }
    catch {
        Write-Error "Error retrieving role assignments: $_"
        return @()
    }
}

function Get-ScEntraPIMAssignments {
    <#
    .SYNOPSIS
        Gets all PIM (Privileged Identity Management) role assignments
    
    .DESCRIPTION
        Retrieves both active and eligible PIM role assignments
    
    .EXAMPLE
        $pimAssignments = Get-ScEntraPIMAssignments
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Test-GraphConnection)) {
        return
    }
    
    Write-Verbose "Retrieving PIM role assignments..."
    
    try {
        # Get role eligibility schedules (eligible assignments)
        $eligibleAssignments = @()
        try {
            $eligibleSchedules = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty Principal, RoleDefinition -ErrorAction SilentlyContinue
            
            foreach ($schedule in $eligibleSchedules) {
                $assignment = [PSCustomObject]@{
                    AssignmentId = $schedule.Id
                    RoleId = $schedule.RoleDefinitionId
                    RoleName = $schedule.RoleDefinition.DisplayName
                    PrincipalId = $schedule.PrincipalId
                    PrincipalType = $schedule.Principal.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', ''
                    AssignmentType = 'PIM-Eligible'
                    Status = $schedule.Status
                    CreatedDateTime = $schedule.CreatedDateTime
                }
                $eligibleAssignments += $assignment
            }
        }
        catch {
            Write-Verbose "Could not retrieve PIM eligible assignments: $_"
        }
        
        # Get role active assignments through PIM
        $activeAssignments = @()
        try {
            $activeSchedules = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ExpandProperty Principal, RoleDefinition -ErrorAction SilentlyContinue
            
            foreach ($schedule in $activeSchedules) {
                $assignment = [PSCustomObject]@{
                    AssignmentId = $schedule.Id
                    RoleId = $schedule.RoleDefinitionId
                    RoleName = $schedule.RoleDefinition.DisplayName
                    PrincipalId = $schedule.PrincipalId
                    PrincipalType = $schedule.Principal.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', ''
                    AssignmentType = 'PIM-Active'
                    Status = $schedule.Status
                    CreatedDateTime = $schedule.CreatedDateTime
                }
                $activeAssignments += $assignment
            }
        }
        catch {
            Write-Verbose "Could not retrieve PIM active assignments: $_"
        }
        
        $allPIMAssignments = $eligibleAssignments + $activeAssignments
        
        Write-Host "Retrieved $($allPIMAssignments.Count) PIM assignments ($($eligibleAssignments.Count) eligible, $($activeAssignments.Count) active)" -ForegroundColor Green
        return $allPIMAssignments
    }
    catch {
        Write-Error "Error retrieving PIM assignments: $_"
        return @()
    }
}

#endregion

#region Escalation Path Analysis

function Get-ScEntraEscalationPaths {
    <#
    .SYNOPSIS
        Analyzes and identifies privilege escalation paths
    
    .DESCRIPTION
        Analyzes nested group memberships, role assignments, and ownership patterns to identify
        potential privilege escalation risks
    
    .PARAMETER Users
        Array of users from Get-ScEntraUsers
    
    .PARAMETER Groups
        Array of groups from Get-ScEntraGroups
    
    .PARAMETER RoleAssignments
        Array of role assignments from Get-ScEntraRoleAssignments
    
    .PARAMETER PIMAssignments
        Array of PIM assignments from Get-ScEntraPIMAssignments
    
    .PARAMETER ServicePrincipals
        Array of service principals from Get-ScEntraServicePrincipals
    
    .PARAMETER AppRegistrations
        Array of app registrations from Get-ScEntraAppRegistrations
    
    .EXAMPLE
        $escalationPaths = Get-ScEntraEscalationPaths -Users $users -Groups $groups -RoleAssignments $roles -PIMAssignments $pim
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Users,
        
        [Parameter(Mandatory = $true)]
        [array]$Groups,
        
        [Parameter(Mandatory = $true)]
        [array]$RoleAssignments,
        
        [Parameter(Mandatory = $false)]
        [array]$PIMAssignments = @(),
        
        [Parameter(Mandatory = $false)]
        [array]$ServicePrincipals = @(),
        
        [Parameter(Mandatory = $false)]
        [array]$AppRegistrations = @()
    )
    
    if (-not (Test-GraphConnection)) {
        return
    }
    
    Write-Verbose "Analyzing escalation paths..."
    
    $escalationRisks = @()
    
    # 1. Analyze role-enabled groups
    $roleEnabledGroups = $Groups | Where-Object { $_.IsAssignableToRole -eq $true }
    Write-Host "Found $($roleEnabledGroups.Count) role-enabled groups" -ForegroundColor Yellow
    
    foreach ($group in $roleEnabledGroups) {
        # Check if this group has role assignments
        $groupRoles = $RoleAssignments | Where-Object { $_.MemberId -eq $group.Id }
        
        if ($groupRoles) {
            try {
                $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
                $owners = Get-MgGroupOwner -GroupId $group.Id -All -ErrorAction SilentlyContinue
                
                foreach ($role in $groupRoles) {
                    $risk = [PSCustomObject]@{
                        RiskType = 'RoleEnabledGroup'
                        Severity = 'High'
                        GroupId = $group.Id
                        GroupName = $group.DisplayName
                        RoleName = $role.RoleName
                        MemberCount = $members.Count
                        OwnerCount = $owners.Count
                        Description = "Role-enabled group '$($group.DisplayName)' has '$($role.RoleName)' role with $($members.Count) members"
                    }
                    $escalationRisks += $risk
                }
            }
            catch {
                Write-Verbose "Could not analyze group $($group.Id): $_"
            }
        }
    }
    
    # 2. Analyze nested group memberships leading to roles
    Write-Verbose "Analyzing nested group memberships..."
    
    $groupsWithRoles = $RoleAssignments | Where-Object { $_.MemberType -eq 'group' } | Select-Object -ExpandProperty MemberId -Unique
    
    foreach ($groupId in $groupsWithRoles) {
        $group = $Groups | Where-Object { $_.Id -eq $groupId }
        if ($group) {
            try {
                # Get transitive members (includes nested groups)
                $transitiveMembers = Get-MgGroupTransitiveMember -GroupId $groupId -All -ErrorAction SilentlyContinue
                $directMembers = Get-MgGroupMember -GroupId $groupId -All -ErrorAction SilentlyContinue
                
                if ($transitiveMembers.Count -gt $directMembers.Count) {
                    $nestedMemberCount = $transitiveMembers.Count - $directMembers.Count
                    $groupRoles = $RoleAssignments | Where-Object { $_.MemberId -eq $groupId }
                    
                    foreach ($role in $groupRoles) {
                        $risk = [PSCustomObject]@{
                            RiskType = 'NestedGroupMembership'
                            Severity = 'Medium'
                            GroupId = $group.Id
                            GroupName = $group.DisplayName
                            RoleName = $role.RoleName
                            DirectMembers = $directMembers.Count
                            NestedMembers = $nestedMemberCount
                            Description = "Group '$($group.DisplayName)' with '$($role.RoleName)' has $nestedMemberCount members through nested groups"
                        }
                        $escalationRisks += $risk
                    }
                }
            }
            catch {
                Write-Verbose "Could not analyze nested members for group ${groupId}: $_"
            }
        }
    }
    
    # 3. Analyze service principal and app ownership
    Write-Verbose "Analyzing service principal and app ownership..."
    
    foreach ($sp in $ServicePrincipals) {
        try {
            $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
            
            if ($owners.Count -gt 0) {
                # Check if SP has any role assignments
                $spRoles = $RoleAssignments | Where-Object { $_.MemberId -eq $sp.Id }
                
                if ($spRoles) {
                    foreach ($role in $spRoles) {
                        $risk = [PSCustomObject]@{
                            RiskType = 'ServicePrincipalOwnership'
                            Severity = 'High'
                            ServicePrincipalId = $sp.Id
                            ServicePrincipalName = $sp.DisplayName
                            RoleName = $role.RoleName
                            OwnerCount = $owners.Count
                            Description = "Service Principal '$($sp.DisplayName)' with '$($role.RoleName)' has $($owners.Count) owners who could potentially abuse permissions"
                        }
                        $escalationRisks += $risk
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not analyze service principal $($sp.Id): $_"
        }
    }
    
    # 4. Analyze app registration ownership
    foreach ($app in $AppRegistrations) {
        try {
            $owners = Get-MgApplicationOwner -ApplicationId $app.Id -All -ErrorAction SilentlyContinue
            
            if ($owners.Count -gt 5) {
                $risk = [PSCustomObject]@{
                    RiskType = 'AppRegistrationOwnership'
                    Severity = 'Medium'
                    AppId = $app.Id
                    AppName = $app.DisplayName
                    OwnerCount = $owners.Count
                    Description = "App Registration '$($app.DisplayName)' has $($owners.Count) owners - potential for credential abuse"
                }
                $escalationRisks += $risk
            }
        }
        catch {
            Write-Verbose "Could not analyze app registration $($app.Id): $_"
        }
    }
    
    # 5. Analyze PIM assignments for unusual patterns
    if ($PIMAssignments.Count -gt 0) {
        Write-Verbose "Analyzing PIM assignment patterns..."
        
        $pimByPrincipal = $PIMAssignments | Group-Object -Property PrincipalId
        
        foreach ($principalGroup in $pimByPrincipal) {
            if ($principalGroup.Count -gt 3) {
                $risk = [PSCustomObject]@{
                    RiskType = 'MultiplePIMRoles'
                    Severity = 'Medium'
                    PrincipalId = $principalGroup.Name
                    PIMRoleCount = $principalGroup.Count
                    Roles = ($principalGroup.Group | Select-Object -ExpandProperty RoleName) -join ', '
                    Description = "Principal has $($principalGroup.Count) PIM role assignments: $($principalGroup.Group | Select-Object -ExpandProperty RoleName -First 3 | Join-String -Separator ', ')..."
                }
                $escalationRisks += $risk
            }
        }
    }
    
    Write-Host "Identified $($escalationRisks.Count) potential escalation risks" -ForegroundColor Yellow
    return $escalationRisks
}

#endregion

#region Reporting Functions

function Export-ScEntraReport {
    <#
    .SYNOPSIS
        Exports analysis results to HTML report with visualizations
    
    .DESCRIPTION
        Generates an interactive HTML report with charts and tables showing the inventory
        and escalation path analysis
    
    .PARAMETER Users
        Array of users
    
    .PARAMETER Groups
        Array of groups
    
    .PARAMETER ServicePrincipals
        Array of service principals
    
    .PARAMETER AppRegistrations
        Array of app registrations
    
    .PARAMETER RoleAssignments
        Array of role assignments
    
    .PARAMETER PIMAssignments
        Array of PIM assignments
    
    .PARAMETER EscalationRisks
        Array of escalation risks
    
    .PARAMETER OutputPath
        Path where to save the HTML report
    
    .EXAMPLE
        Export-ScEntraReport -Users $users -Groups $groups -OutputPath "C:\Reports\entra-report.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Users,
        
        [Parameter(Mandatory = $true)]
        [array]$Groups,
        
        [Parameter(Mandatory = $true)]
        [array]$ServicePrincipals,
        
        [Parameter(Mandatory = $true)]
        [array]$AppRegistrations,
        
        [Parameter(Mandatory = $true)]
        [array]$RoleAssignments,
        
        [Parameter(Mandatory = $false)]
        [array]$PIMAssignments = @(),
        
        [Parameter(Mandatory = $false)]
        [array]$EscalationRisks = @(),
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "./ScEntra-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    )
    
    Write-Verbose "Generating HTML report..."
    
    # Prepare statistics
    $stats = @{
        TotalUsers = $Users.Count
        EnabledUsers = ($Users | Where-Object { $_.AccountEnabled -eq $true }).Count
        TotalGroups = $Groups.Count
        RoleEnabledGroups = ($Groups | Where-Object { $_.IsAssignableToRole -eq $true }).Count
        SecurityGroups = ($Groups | Where-Object { $_.SecurityEnabled -eq $true }).Count
        TotalServicePrincipals = $ServicePrincipals.Count
        EnabledServicePrincipals = ($ServicePrincipals | Where-Object { $_.AccountEnabled -eq $true }).Count
        TotalAppRegistrations = $AppRegistrations.Count
        TotalRoleAssignments = $RoleAssignments.Count
        TotalPIMAssignments = $PIMAssignments.Count
        TotalEscalationRisks = $EscalationRisks.Count
        HighSeverityRisks = ($EscalationRisks | Where-Object { $_.Severity -eq 'High' }).Count
        MediumSeverityRisks = ($EscalationRisks | Where-Object { $_.Severity -eq 'Medium' }).Count
    }
    
    # Get role distribution
    $roleDistribution = $RoleAssignments | Group-Object -Property RoleName | 
        Select-Object @{N='Role';E={$_.Name}}, Count | 
        Sort-Object -Property Count -Descending | 
        Select-Object -First 10
    
    # Get risk type distribution
    $riskDistribution = $EscalationRisks | Group-Object -Property RiskType | 
        Select-Object @{N='RiskType';E={$_.Name}}, Count
    
    # Build HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScEntra Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }
        
        .stat-card h3 {
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }
        
        .stat-card.warning .number {
            color: #ff6b6b;
        }
        
        .section {
            padding: 40px;
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        
        .chart-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-top: 20px;
        }
        
        .chart-box {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .chart-box h3 {
            color: #333;
            margin-bottom: 15px;
            text-align: center;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        
        th {
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .severity-high {
            color: #dc3545;
            font-weight: bold;
        }
        
        .severity-medium {
            color: #ffc107;
            font-weight: bold;
        }
        
        .severity-low {
            color: #28a745;
            font-weight: bold;
        }
        
        footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            margin-top: 40px;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .badge-high {
            background: #dc3545;
            color: white;
        }
        
        .badge-medium {
            background: #ffc107;
            color: #333;
        }
        
        .badge-low {
            background: #28a745;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 ScEntra Analysis Report</h1>
            <p>Entra ID Security Analysis - Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Users</h3>
                <div class="number">$($stats.TotalUsers)</div>
            </div>
            <div class="stat-card">
                <h3>Enabled Users</h3>
                <div class="number">$($stats.EnabledUsers)</div>
            </div>
            <div class="stat-card">
                <h3>Total Groups</h3>
                <div class="number">$($stats.TotalGroups)</div>
            </div>
            <div class="stat-card">
                <h3>Role-Enabled Groups</h3>
                <div class="number">$($stats.RoleEnabledGroups)</div>
            </div>
            <div class="stat-card">
                <h3>Service Principals</h3>
                <div class="number">$($stats.TotalServicePrincipals)</div>
            </div>
            <div class="stat-card">
                <h3>App Registrations</h3>
                <div class="number">$($stats.TotalAppRegistrations)</div>
            </div>
            <div class="stat-card">
                <h3>Role Assignments</h3>
                <div class="number">$($stats.TotalRoleAssignments)</div>
            </div>
            <div class="stat-card">
                <h3>PIM Assignments</h3>
                <div class="number">$($stats.TotalPIMAssignments)</div>
            </div>
            <div class="stat-card warning">
                <h3>Escalation Risks</h3>
                <div class="number">$($stats.TotalEscalationRisks)</div>
            </div>
            <div class="stat-card warning">
                <h3>High Severity</h3>
                <div class="number">$($stats.HighSeverityRisks)</div>
            </div>
            <div class="stat-card warning">
                <h3>Medium Severity</h3>
                <div class="number">$($stats.MediumSeverityRisks)</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Distribution Charts</h2>
            <div class="chart-container">
                <div class="chart-box">
                    <h3>Top 10 Role Assignments</h3>
                    <canvas id="roleChart"></canvas>
                </div>
                <div class="chart-box">
                    <h3>Escalation Risk Types</h3>
                    <canvas id="riskChart"></canvas>
                </div>
            </div>
        </div>
"@

    if ($EscalationRisks.Count -gt 0) {
        $html += @"
        
        <div class="section">
            <h2>⚠️ Escalation Risks</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Risk Type</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($risk in ($EscalationRisks | Sort-Object -Property Severity -Descending)) {
            $badgeClass = switch ($risk.Severity) {
                'High' { 'badge-high' }
                'Medium' { 'badge-medium' }
                'Low' { 'badge-low' }
                default { 'badge-medium' }
            }
            
            $html += @"
                    <tr>
                        <td><span class="badge $badgeClass">$($risk.Severity)</span></td>
                        <td>$($risk.RiskType)</td>
                        <td>$($risk.Description)</td>
                    </tr>
"@
        }
        
        $html += @"
                </tbody>
            </table>
        </div>
"@
    }

    $html += @"
        
        <footer>
            <p>Generated by ScEntra - Entra ID Security Scanner</p>
            <p>Report generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </footer>
    </div>
    
    <script>
        // Role Distribution Chart
        const roleCtx = document.getElementById('roleChart');
        new Chart(roleCtx, {
            type: 'bar',
            data: {
                labels: [$($roleDistribution | ForEach-Object { "'$($_.Role)'" } | Join-String -Separator ', ')],
                datasets: [{
                    label: 'Number of Assignments',
                    data: [$($roleDistribution | ForEach-Object { $_.Count } | Join-String -Separator ', ')],
                    backgroundColor: 'rgba(102, 126, 234, 0.7)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
        
        // Risk Distribution Chart
        const riskCtx = document.getElementById('riskChart');
        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: [$($riskDistribution | ForEach-Object { "'$($_.RiskType)'" } | Join-String -Separator ', ')],
                datasets: [{
                    data: [$($riskDistribution | ForEach-Object { $_.Count } | Join-String -Separator ', ')],
                    backgroundColor: [
                        'rgba(220, 53, 69, 0.7)',
                        'rgba(255, 193, 7, 0.7)',
                        'rgba(40, 167, 69, 0.7)',
                        'rgba(102, 126, 234, 0.7)',
                        'rgba(118, 75, 162, 0.7)'
                    ],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    </script>
</body>
</html>
"@

    # Write HTML to file
    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "Report generated successfully: $OutputPath" -ForegroundColor Green
        
        # Also export to JSON for programmatic access
        $jsonPath = $OutputPath -replace '\.html$', '.json'
        
        $jsonData = @{
            GeneratedAt = Get-Date -Format 'o'
            Statistics = $stats
            Users = $Users | Select-Object Id, DisplayName, UserPrincipalName, AccountEnabled, UserType
            Groups = $Groups | Select-Object Id, DisplayName, IsAssignableToRole, SecurityEnabled, MemberCount
            ServicePrincipals = $ServicePrincipals | Select-Object Id, DisplayName, AppId, AccountEnabled
            AppRegistrations = $AppRegistrations | Select-Object Id, DisplayName, AppId
            RoleAssignments = $RoleAssignments
            PIMAssignments = $PIMAssignments
            EscalationRisks = $EscalationRisks
        }
        
        $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host "JSON data exported to: $jsonPath" -ForegroundColor Green
        
        return $OutputPath
    }
    catch {
        Write-Error "Error generating report: $_"
        return $null
    }
}

#endregion

#region Main Analysis Function

function Invoke-ScEntraAnalysis {
    <#
    .SYNOPSIS
        Main function to perform complete Entra ID security analysis
    
    .DESCRIPTION
        Orchestrates the complete analysis workflow:
        1. Connects to Microsoft Graph (if not already connected)
        2. Inventories all identity objects (users, groups, service principals, apps)
        3. Enumerates role assignments (direct and PIM)
        4. Analyzes escalation paths
        5. Generates HTML and JSON reports
    
    .PARAMETER OutputPath
        Path where to save the report (default: current directory)
    
    .PARAMETER SkipConnection
        Skip the connection check/prompt (assumes already connected)
    
    .EXAMPLE
        Invoke-ScEntraAnalysis
        
    .EXAMPLE
        Invoke-ScEntraAnalysis -OutputPath "C:\Reports\entra-report.html"
        
    .EXAMPLE
        Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "Application.Read.All", "RoleManagement.Read.Directory"
        Invoke-ScEntraAnalysis -SkipConnection
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "./ScEntra-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html",
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipConnection
    )
    
    Write-Host @"
    
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ███████╗ ██████╗███████╗███╗   ██╗████████╗██████╗ █████╗   ║
║   ██╔════╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗  ║
║   ███████╗██║     █████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║  ║
║   ╚════██║██║     ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║  ║
║   ███████║╚██████╗███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║  ║
║   ╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝  ║
║                                                           ║
║        Scan Entra for Risk & Escalation Paths            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    # Check Graph connection
    if (-not $SkipConnection) {
        $context = Get-MgContext
        if ($null -eq $context) {
            Write-Host "`nNot connected to Microsoft Graph." -ForegroundColor Yellow
            Write-Host "Connecting with required scopes..." -ForegroundColor Cyan
            
            $requiredScopes = @(
                "User.Read.All"
                "Group.Read.All"
                "Application.Read.All"
                "RoleManagement.Read.Directory"
                "RoleEligibilitySchedule.Read.Directory"
                "RoleAssignmentSchedule.Read.Directory"
            )
            
            try {
                Connect-MgGraph -Scopes $requiredScopes -NoWelcome
                Write-Host "✓ Connected successfully" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to connect to Microsoft Graph: $_"
                return
            }
        }
        else {
            Write-Host "✓ Already connected to Microsoft Graph" -ForegroundColor Green
        }
    }
    
    $startTime = Get-Date
    
    # Step 1: Inventory
    Write-Host "`n[1/5] 📋 Collecting Inventory..." -ForegroundColor Cyan
    Write-Host "=" * 60
    
    $users = Get-ScEntraUsers
    $groups = Get-ScEntraGroups
    $servicePrincipals = Get-ScEntraServicePrincipals
    $appRegistrations = Get-ScEntraAppRegistrations
    
    # Step 2: Role Assignments
    Write-Host "`n[2/5] 👑 Enumerating Role Assignments..." -ForegroundColor Cyan
    Write-Host "=" * 60
    
    $roleAssignments = Get-ScEntraRoleAssignments
    
    # Step 3: PIM Assignments
    Write-Host "`n[3/5] 🔐 Checking PIM Assignments..." -ForegroundColor Cyan
    Write-Host "=" * 60
    
    $pimAssignments = Get-ScEntraPIMAssignments
    
    # Step 4: Escalation Analysis
    Write-Host "`n[4/5] 🔍 Analyzing Escalation Paths..." -ForegroundColor Cyan
    Write-Host "=" * 60
    
    $escalationRisks = Get-ScEntraEscalationPaths `
        -Users $users `
        -Groups $groups `
        -RoleAssignments $roleAssignments `
        -PIMAssignments $pimAssignments `
        -ServicePrincipals $servicePrincipals `
        -AppRegistrations $appRegistrations
    
    # Step 5: Generate Report
    Write-Host "`n[5/5] 📊 Generating Report..." -ForegroundColor Cyan
    Write-Host "=" * 60
    
    $reportPath = Export-ScEntraReport `
        -Users $users `
        -Groups $groups `
        -ServicePrincipals $servicePrincipals `
        -AppRegistrations $appRegistrations `
        -RoleAssignments $roleAssignments `
        -PIMAssignments $pimAssignments `
        -EscalationRisks $escalationRisks `
        -OutputPath $OutputPath
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    # Summary
    Write-Host "`n" + ("=" * 60) -ForegroundColor Green
    Write-Host "✓ Analysis Complete!" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host "`nSummary:"
    Write-Host "  • Users: $($users.Count)" -ForegroundColor White
    Write-Host "  • Groups: $($groups.Count)" -ForegroundColor White
    Write-Host "  • Service Principals: $($servicePrincipals.Count)" -ForegroundColor White
    Write-Host "  • App Registrations: $($appRegistrations.Count)" -ForegroundColor White
    Write-Host "  • Role Assignments: $($roleAssignments.Count)" -ForegroundColor White
    Write-Host "  • PIM Assignments: $($pimAssignments.Count)" -ForegroundColor White
    Write-Host "  • Escalation Risks: $($escalationRisks.Count)" -ForegroundColor Yellow
    Write-Host "`nReport Location: $reportPath" -ForegroundColor Cyan
    Write-Host "Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor Gray
    
    return @{
        Users = $users
        Groups = $groups
        ServicePrincipals = $servicePrincipals
        AppRegistrations = $appRegistrations
        RoleAssignments = $roleAssignments
        PIMAssignments = $pimAssignments
        EscalationRisks = $escalationRisks
        ReportPath = $reportPath
    }
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    'Invoke-ScEntraAnalysis'
    'Get-ScEntraUsers'
    'Get-ScEntraGroups'
    'Get-ScEntraServicePrincipals'
    'Get-ScEntraAppRegistrations'
    'Get-ScEntraRoleAssignments'
    'Get-ScEntraPIMAssignments'
    'Get-ScEntraEscalationPaths'
    'Export-ScEntraReport'
)
