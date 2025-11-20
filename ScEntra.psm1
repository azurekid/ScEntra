#Requires -Version 7.0

<#
.SYNOPSIS
    ScEntra - Scan Entra for risk in role assignments and escalation paths

.DESCRIPTION
    This module provides functions to inventory Entra ID objects (users, groups, service principals, app registrations)
    and analyze privilege escalation risks through role assignments, PIM, and nested group memberships.
    
    This module uses direct Microsoft Graph REST API endpoints for maximum compatibility and control.
#>

#region Module Initialization
$privateFolder = Join-Path -Path $PSScriptRoot -ChildPath 'Private'
if (Test-Path $privateFolder) {
    Get-ChildItem -Path $privateFolder -Filter '*.ps1' | ForEach-Object { . $_.FullName }
}

$publicFolder = Join-Path -Path $PSScriptRoot -ChildPath 'Public'
if (Test-Path $publicFolder) {
    Get-ChildItem -Path $publicFolder -Filter '*.ps1' | ForEach-Object { . $_.FullName }
}
#endregion

#region Helper Functions

# Module-level variable to store access token
$script:GraphAccessToken = $null
$script:GraphApiVersion = 'v1.0'
$script:GraphBaseUrl = "https://graph.microsoft.com/$script:GraphApiVersion"

function Connect-ScEntraGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph API and obtains an access token
    
    .DESCRIPTION
        Authenticates to Microsoft Graph using device code flow or existing access token
    
    .PARAMETER AccessToken
        Existing access token to use for authentication
    
    .PARAMETER Scopes
        Array of permission scopes required
    
    .PARAMETER TenantId
        The tenant ID to authenticate against
    
    .EXAMPLE
        Connect-ScEntraGraph -Scopes "User.Read.All", "Group.Read.All"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Scopes = @(
            "User.Read.All",
            "Group.Read.All",
            "Application.Read.All",
            "RoleManagement.Read.Directory",
            "RoleEligibilitySchedule.Read.Directory",
            "RoleAssignmentSchedule.Read.Directory",
            "PrivilegedAccess.Read.AzureADGroup"
        ),
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId = "common"
    )
    
    if ($AccessToken) {
        $script:GraphAccessToken = $AccessToken
        Write-Verbose "Using provided access token"
        return $true
    }
    
    # Use Azure PowerShell or Azure CLI to get token if available
    try {
        # Try Azure PowerShell
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($azContext) {
            $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction SilentlyContinue
            if ($token) {
                $script:GraphAccessToken = $token.Token | ConvertFrom-SecureString -AsPlainText
                Write-Host "✓ Authenticated using Azure PowerShell context" -ForegroundColor Green
                return $true
            }
        }
    }
    catch {
        Write-Verbose "Azure PowerShell not available: $_"
    }
    
    try {
        # Try Azure CLI
        $cliToken = az account get-access-token --resource https://graph.microsoft.com 2>$null | ConvertFrom-Json
        if ($cliToken -and $cliToken.accessToken) {
            $script:GraphAccessToken = $cliToken.accessToken
            Write-Host "✓ Authenticated using Azure CLI" -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Verbose "Azure CLI not available: $_"
    }
    
    # If we reach here, we need interactive authentication
    Write-Warning "No existing authentication found. Please provide an access token or authenticate using Azure PowerShell/CLI first."
    Write-Host "`nTo authenticate, use one of the following methods:" -ForegroundColor Yellow
    Write-Host "1. Azure PowerShell: Connect-AzAccount" -ForegroundColor Cyan
    Write-Host "2. Azure CLI: az login" -ForegroundColor Cyan
    Write-Host "3. Provide access token: Connect-ScEntraGraph -AccessToken <token>" -ForegroundColor Cyan
    
    return $false
}

function Test-GraphConnection {
    <#
    .SYNOPSIS
        Tests if connected to Microsoft Graph
    #>
    if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
        Write-Warning "Not connected to Microsoft Graph. Please run Connect-ScEntraGraph first."
        return $false
    }
    
    # Test the token by making a simple request
    # Using /organization endpoint instead of /me because /me doesn't work with Service Principal authentication
    try {
        $null = Invoke-GraphRequest -Uri "$script:GraphBaseUrl/organization" -Method GET -ErrorAction Stop
        return $true
    }
    catch {
        Write-Warning "Graph connection test failed. Token may be expired. Please re-authenticate."
        return $false
    }
}

function Invoke-GraphRequest {
    <#
    .SYNOPSIS
        Makes a REST API request to Microsoft Graph
    
    .PARAMETER Uri
        The URI to call
    
    .PARAMETER Method
        HTTP method (GET, POST, PATCH, DELETE)
    
    .PARAMETER Body
        Request body for POST/PATCH requests
    
    .EXAMPLE
        Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/users" -Method GET
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $false)]
        [string]$Method = 'GET',
        
        [Parameter(Mandatory = $false)]
        [object]$Body
    )
    
    if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
        throw "Not authenticated. Please run Connect-ScEntraGraph first."
    }
    
    $headers = @{
        'Authorization' = "Bearer $script:GraphAccessToken"
        'Content-Type' = 'application/json'
        'ConsistencyLevel' = 'eventual'
    }
    
    $params = @{
        Uri = $Uri
        Method = $Method
        Headers = $headers
    }
    
    if ($Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 10)
    }
    
    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop
        return $response
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($_.ErrorDetails.Message) {
            $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($errorDetails.error.message) {
                $errorMessage = $errorDetails.error.message
            }
        }
        Write-Error "Graph API request failed: $errorMessage"
        throw
    }
}

function Get-AllGraphItems {
    <#
    .SYNOPSIS
        Helper function to get all items from Graph API with pagination
    
    .PARAMETER Uri
        The Graph API endpoint URI
    
    .PARAMETER Method
        HTTP method (default: GET)
    
    .PARAMETER ProgressActivity
        Optional activity name to display in progress bar
    
    .EXAMPLE
        Get-AllGraphItems -Uri "https://graph.microsoft.com/v1.0/users"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $false)]
        [string]$Method = 'GET',
        
        [Parameter(Mandatory = $false)]
        [string]$ProgressActivity = $null
    )
    
    $allItems = @()
    $nextLink = $Uri
    $pageCount = 0
    
    do {
        try {
            $pageCount++
            
            if ($ProgressActivity) {
                Write-Progress -Activity $ProgressActivity -Status "Fetching page $pageCount (retrieved $($allItems.Count) items so far)" -Id 1
            }
            
            $result = Invoke-GraphRequest -Uri $nextLink -Method $Method
            
            # Handle both paginated and non-paginated responses
            if ($result.value) {
                $allItems += $result.value
            }
            elseif ($result) {
                $allItems += $result
            }
            
            # Get next page link
            $nextLink = $result.'@odata.nextLink'
        }
        catch {
            Write-Error "Error fetching items from $nextLink : $_"
            break
        }
    } while ($nextLink)
    
    if ($ProgressActivity) {
        Write-Progress -Activity $ProgressActivity -Completed -Id 1
    }
    
    return $allItems
}

function Invoke-GraphBatchRequest {
    <#
    .SYNOPSIS
        Makes a batch request to Microsoft Graph API for multiple operations
    
    .PARAMETER Requests
        Array of request objects with id, method, and url properties
    
    .PARAMETER MaxBatchSize
        Maximum number of requests per batch (default: 20, Graph API limit)
    
    .EXAMPLE
        $requests = @(
            @{ id = "1"; method = "GET"; url = "/groups/id1/members" }
            @{ id = "2"; method = "GET"; url = "/groups/id2/members" }
        )
        Invoke-GraphBatchRequest -Requests $requests
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Requests,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxBatchSize = 20
    )
    
    if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
        throw "Not authenticated. Please run Connect-ScEntraGraph first."
    }
    
    $allResponses = @{}
    $batches = @()
    
    # Split requests into batches of MaxBatchSize
    for ($i = 0; $i -lt $Requests.Count; $i += $MaxBatchSize) {
        $batchSize = [Math]::Min($MaxBatchSize, $Requests.Count - $i)
        $batches += ,@($Requests[$i..($i + $batchSize - 1)])
    }
    
    Write-Verbose "Processing $($Requests.Count) requests in $($batches.Count) batches"
    
    foreach ($batch in $batches) {
        $batchBody = @{
            requests = $batch
        }
        
        try {
            $headers = @{
                'Authorization' = "Bearer $script:GraphAccessToken"
                'Content-Type' = 'application/json'
            }
            
            $batchUri = "$script:GraphBaseUrl/`$batch"
            $response = Invoke-RestMethod -Uri $batchUri -Method POST -Headers $headers -Body ($batchBody | ConvertTo-Json -Depth 10) -ErrorAction Stop
            
            # Process responses
            foreach ($resp in $response.responses) {
                $allResponses[$resp.id] = $resp
            }
        }
        catch {
            Write-Error "Batch request failed: $_"
            throw
        }
    }
    
    return $allResponses
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
        $select = "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,userType,onPremisesSyncEnabled"
        $uri = "$script:GraphBaseUrl/users?`$top=999&`$select=$select"
        
        $users = Get-AllGraphItems -Uri $uri -ProgressActivity "Retrieving users from Entra ID"
        
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
        Retrieves comprehensive information about all groups including role-enabled status.
        Member counts are fetched on-demand only for groups relevant to role analysis.
    
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
        $select = "id,displayName,description,groupTypes,securityEnabled,mailEnabled,isAssignableToRole,createdDateTime,membershipRule,membershipRuleProcessingState"
        $uri = "$script:GraphBaseUrl/groups?`$top=999&`$select=$select"
        
        $groups = Get-AllGraphItems -Uri $uri -ProgressActivity "Retrieving groups from Entra ID"

        # PIM enablement is independent from the isAssignableToRole flag (https://learn.microsoft.com/entra/id-governance/privileged-identity-management/concept-pim-for-groups#relationship-between-role-assignable-groups-and-pim-for-groups)
        # Note: We discover PIM-enabled groups indirectly by checking each group's PIM role assignments endpoint
        # The privilegedAccess schedule list endpoints require groupId/principalId filters and cannot enumerate all groups
        $pimEnabledGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        
        # Query PIM role assignments to discover which groups are PIM-enabled
        # This endpoint returns assignments where groups are assigned to directory roles via PIM
        try {
            $pimRoleAssignments = Get-AllGraphItems -Uri "$script:GraphBaseUrl/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal" -ProgressActivity "Discovering PIM-enabled groups via role assignments"
            if ($pimRoleAssignments) {
                foreach ($assignment in $pimRoleAssignments) {
                    if ($assignment.principal.'@odata.type' -eq '#microsoft.graph.group' -and $assignment.principal.id) {
                        $null = $pimEnabledGroupIds.Add($assignment.principal.id)
                    }
                }
            }
        }
        catch {
            Write-Verbose "Unable to retrieve PIM role assignments for group discovery: $_"
        }

        foreach ($group in $groups) {
            $group | Add-Member -NotePropertyName 'isPIMEnabled' -NotePropertyValue ($pimEnabledGroupIds.Contains($group.id)) -Force
        }

        if ($pimEnabledGroupIds.Count -gt 0) {
            Write-Host "Detected $($pimEnabledGroupIds.Count) PIM-enabled groups via role eligibility schedules" -ForegroundColor Yellow
        }
        else {
            Write-Verbose "No groups with PIM role eligibility were found."
        }
        
        Write-Host "Retrieved $($groups.Count) groups" -ForegroundColor Green
        Write-Verbose "Member counts will be fetched on-demand for groups with role assignments or PIM eligibility"
        
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
        $select = "id,displayName,appId,servicePrincipalType,accountEnabled,createdDateTime,appOwnerOrganizationId"
        $uri = "$script:GraphBaseUrl/servicePrincipals?`$top=999&`$select=$select"
        
        $servicePrincipals = Get-AllGraphItems -Uri $uri -ProgressActivity "Retrieving service principals from Entra ID"
        
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
        $select = "id,displayName,appId,createdDateTime,signInAudience,publisherDomain"
        $uri = "$script:GraphBaseUrl/applications?`$top=999&`$select=$select"
        
        $apps = Get-AllGraphItems -Uri $uri -ProgressActivity "Retrieving app registrations from Entra ID"
        
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
        $rolesUri = "$script:GraphBaseUrl/directoryRoles?`$select=id,displayName,description"
        $roles = Get-AllGraphItems -Uri $rolesUri -ProgressActivity "Retrieving directory roles"
        
        $allAssignments = @()
        $roleCount = 0
        $totalRoles = $roles.Count
        
        foreach ($role in $roles) {
            $roleCount++
            $percentComplete = [math]::Round(($roleCount / $totalRoles) * 100)
            Write-Progress -Activity "Enumerating role assignments" -Status "Processing role $roleCount of $totalRoles - $($role.displayName)" -PercentComplete $percentComplete -Id 3
            Write-Verbose "Processing role: $($role.displayName)"
            
            $membersUri = "$script:GraphBaseUrl/directoryRoles/$($role.id)/members?`$select=id"
            $members = Get-AllGraphItems -Uri $membersUri
            
            foreach ($member in $members) {
                $assignment = [PSCustomObject]@{
                    RoleId = $role.id
                    RoleName = $role.displayName
                    RoleDescription = $role.description
                    MemberId = $member.id
                    MemberType = if ($member.'@odata.type') { 
                        $member.'@odata.type' -replace '#microsoft.graph.', '' 
                    } else { 
                        'unknown' 
                    }
                    AssignmentType = 'Direct'
                }
                $allAssignments += $assignment
            }
        }
        
        Write-Progress -Activity "Enumerating role assignments" -Completed -Id 3
        
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
            Write-Progress -Activity "Retrieving PIM assignments" -Status "Fetching eligible role assignments" -PercentComplete 25 -Id 4
            $eligibleUri = "$script:GraphBaseUrl/roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition"
            $eligibleSchedules = Get-AllGraphItems -Uri $eligibleUri -ErrorAction SilentlyContinue
            
            foreach ($schedule in $eligibleSchedules) {
                $assignment = [PSCustomObject]@{
                    AssignmentId = $schedule.id
                    RoleId = $schedule.roleDefinitionId
                    RoleName = if ($schedule.roleDefinition) { $schedule.roleDefinition.displayName } else { 'Unknown' }
                    PrincipalId = $schedule.principalId
                    PrincipalDisplayName = if ($schedule.principal) { $schedule.principal.displayName } else { 'Unknown' }
                    PrincipalType = if ($schedule.principal -and $schedule.principal.'@odata.type') {
                        $schedule.principal.'@odata.type' -replace '#microsoft.graph.', ''
                    } else {
                        'unknown'
                    }
                    AssignmentType = 'PIM-Eligible'
                    Status = $schedule.status
                    CreatedDateTime = $schedule.createdDateTime
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
            Write-Progress -Activity "Retrieving PIM assignments" -Status "Fetching active role assignments" -PercentComplete 75 -Id 4
            $activeUri = "$script:GraphBaseUrl/roleManagement/directory/roleAssignmentSchedules?`$expand=principal,roleDefinition"
            $activeSchedules = Get-AllGraphItems -Uri $activeUri -ErrorAction SilentlyContinue
            
            foreach ($schedule in $activeSchedules) {
                $assignment = [PSCustomObject]@{
                    AssignmentId = $schedule.id
                    RoleId = $schedule.roleDefinitionId
                    RoleName = if ($schedule.roleDefinition) { $schedule.roleDefinition.displayName } else { 'Unknown' }
                    PrincipalId = $schedule.principalId
                    PrincipalDisplayName = if ($schedule.principal) { $schedule.principal.displayName } else { 'Unknown' }
                    PrincipalType = if ($schedule.principal -and $schedule.principal.'@odata.type') {
                        $schedule.principal.'@odata.type' -replace '#microsoft.graph.', ''
                    } else {
                        'unknown'
                    }
                    AssignmentType = 'PIM-Active'
                    Status = $schedule.status
                    CreatedDateTime = $schedule.createdDateTime
                }
                $activeAssignments += $assignment
            }
        }
        catch {
            Write-Verbose "Could not retrieve PIM active assignments: $_"
        }
        
        Write-Progress -Activity "Retrieving PIM assignments" -Completed -Id 4
        
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

function New-ScEntraGraphData {
    <#
    .SYNOPSIS
        Builds graph data structure for visualization of escalation paths
    
    .DESCRIPTION
        Creates nodes and edges representing the relationships between users, groups, 
        service principals, app registrations, and role assignments for graph visualization
    
    .PARAMETER Users
        Array of users
    
    .PARAMETER Groups
        Array of groups
    
    .PARAMETER ServicePrincipals
        Array of service principals
    
    .PARAMETER AppRegistrations
        Array of app registrations
    
    .PARAMETER RoleAssignments
        Array of role assignments (includes both direct and PIM)
    
    .PARAMETER PIMAssignments
        Array of PIM assignments
    
    .PARAMETER GroupMemberships
        Hashtable of group memberships (groupId -> array of member objects)
    
    .PARAMETER GroupOwners
        Hashtable of group owners (groupId -> array of owner objects)
    
    .PARAMETER SPOwners
        Hashtable of service principal owners (spId -> array of owner objects)
    
    .PARAMETER SPAppRoleAssignments
        Hashtable of service principal app role assignments (spId -> array of principal objects)
    
    .PARAMETER AppOwners
        Hashtable of app registration owners (appId -> array of owner objects)
    
    .EXAMPLE
        $graphData = New-ScEntraGraphData -Users $users -Groups $groups -RoleAssignments $roles
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Users,
        
        [Parameter(Mandatory = $true)]
        [array]$Groups,
        
        [Parameter(Mandatory = $false)]
        [array]$ServicePrincipals = @(),
        
        [Parameter(Mandatory = $false)]
        [array]$AppRegistrations = @(),
        
        [Parameter(Mandatory = $true)]
        [array]$RoleAssignments,
        
        [Parameter(Mandatory = $false)]
        [array]$PIMAssignments = @(),
        
        [Parameter(Mandatory = $false)]
        [hashtable]$GroupMemberships = @{},
        
        [Parameter(Mandatory = $false)]
        [hashtable]$GroupOwners = @{},
        
        [Parameter(Mandatory = $false)]
        [hashtable]$SPOwners = @{},
        
        [Parameter(Mandatory = $false)]
        [hashtable]$SPAppRoleAssignments = @{},
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AppOwners = @{}
    )
    
    Write-Verbose "Building graph data structure..."
    
    $nodes = [System.Collections.ArrayList]::new()
    $edges = [System.Collections.ArrayList]::new()
    $nodeIndex = @{}
    $resolveGroupShape = {
        param($group)
        if (-not $group) {
            return 'box'
        }

        if (($group.PSObject.Properties.Name -contains 'isPIMEnabled') -and $group.isPIMEnabled) {
            return 'diamond'
        }
        elseif ($group.securityEnabled) {
            return 'triangle'
        }

        return 'box'
    }
    
    # Define high-privilege roles for escalation path analysis
    $highPrivilegeRoles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Security Administrator',
        'Cloud Application Administrator',
        'Application Administrator',
        'User Administrator',
        'Exchange Administrator',
        'SharePoint Administrator',
        'Global Reader',
        'Security Reader'
    )
    
    # Add role nodes (only for roles that have assignments)
    $assignedRoles = @($RoleAssignments | Select-Object -ExpandProperty RoleName -Unique)
    $pimRoles = @($PIMAssignments | Select-Object -ExpandProperty RoleName -Unique)
    $allRoles = @($assignedRoles; $pimRoles) | Select-Object -Unique
    
    foreach ($roleName in $allRoles) {
        $roleId = "role-$roleName"
        if (-not $nodeIndex.ContainsKey($roleId)) {
            $isHighPrivilege = $highPrivilegeRoles -contains $roleName
            $null = $nodes.Add(@{
                id = $roleId
                label = $roleName
                type = 'role'
                isPrivileged = $true
                isHighPrivilege = $isHighPrivilege
            })
            $nodeIndex[$roleId] = $nodes.Count - 1
        }
    }
    
    # Add nodes and edges for direct role assignments
    foreach ($assignment in $RoleAssignments) {
        $roleId = "role-$($assignment.RoleName)"
        
        # Determine the principal type and add node
        switch ($assignment.MemberType) {
            'user' {
                $user = $Users | Where-Object { $_.id -eq $assignment.MemberId } | Select-Object -First 1
                if ($user) {
                    if (-not $nodeIndex.ContainsKey($user.id)) {
                        $null = $nodes.Add(@{
                            id = $user.id
                            label = $user.displayName
                            type = 'user'
                            userPrincipalName = $user.userPrincipalName
                            accountEnabled = $user.accountEnabled
                        })
                        $nodeIndex[$user.id] = $nodes.Count - 1
                    }
                    $null = $edges.Add(@{
                        from = $user.id
                        to = $roleId
                        type = 'has_role'
                        label = 'Direct'
                    })
                }
            }
            'group' {
                $group = $Groups | Where-Object { $_.id -eq $assignment.MemberId } | Select-Object -First 1
                    if ($group) {
                    if (-not $nodeIndex.ContainsKey($group.id)) {
                        $groupShape = & $resolveGroupShape $group
                        $null = $nodes.Add(@{
                            id = $group.id
                            label = $group.displayName
                            type = 'group'
                            shape = $groupShape
                            isPIMEnabled = [bool]$group.isPIMEnabled
                            isAssignableToRole = $group.isAssignableToRole
                            securityEnabled = $group.securityEnabled
                        })
                        $nodeIndex[$group.id] = $nodes.Count - 1
                    }
                    $null = $edges.Add(@{
                        from = $group.id
                        to = $roleId
                        type = 'has_role'
                        label = 'Direct'
                    })
                }
            }
            'servicePrincipal' {
                $sp = $ServicePrincipals | Where-Object { $_.id -eq $assignment.MemberId } | Select-Object -First 1
                if ($sp) {
                    if (-not $nodeIndex.ContainsKey($sp.id)) {
                        $null = $nodes.Add(@{
                            id = $sp.id
                            label = $sp.displayName
                            type = 'servicePrincipal'
                            appId = $sp.appId
                            accountEnabled = $sp.accountEnabled
                        })
                        $nodeIndex[$sp.id] = $nodes.Count - 1
                    }
                    $null = $edges.Add(@{
                        from = $sp.id
                        to = $roleId
                        type = 'has_role'
                        label = 'Direct'
                    })
                }
            }
        }
    }
    
    # Add nodes and edges for PIM assignments (eligible)
    Write-Verbose "Processing $($PIMAssignments.Count) PIM assignments..."
    foreach ($pimAssignment in $PIMAssignments) {
        $roleId = "role-$($pimAssignment.RoleName)"
        $assignmentLabel = if ($pimAssignment.AssignmentType -eq 'PIM-Eligible') { 'Eligible' } else { 'PIM Active' }
        Write-Verbose "  PIM: $($pimAssignment.PrincipalType) $($pimAssignment.PrincipalId) -> $($pimAssignment.RoleName)"
        
        # Determine the principal type and add node
        switch ($pimAssignment.PrincipalType) {
            'user' {
                $user = $Users | Where-Object { $_.id -eq $pimAssignment.PrincipalId } | Select-Object -First 1
                if ($user) {
                    if (-not $nodeIndex.ContainsKey($user.id)) {
                        $null = $nodes.Add(@{
                            id = $user.id
                            label = $user.displayName
                            type = 'user'
                            userPrincipalName = $user.userPrincipalName
                            accountEnabled = $user.accountEnabled
                        })
                        $nodeIndex[$user.id] = $nodes.Count - 1
                    }
                    $null = $edges.Add(@{
                        from = $user.id
                        to = $roleId
                        type = 'has_role'
                        label = $assignmentLabel
                        isPIM = $true
                    })
                }
            }
            'group' {
                $group = $Groups | Where-Object { $_.id -eq $pimAssignment.PrincipalId } | Select-Object -First 1
                Write-Verbose "    Found group: $($group -ne $null) - $($group.displayName) - ID: $($pimAssignment.PrincipalId)"
                if ($group) {
                    if (-not $nodeIndex.ContainsKey($group.id)) {
                        Write-Verbose "      Adding group node: $($group.displayName)"
                        $groupShape = & $resolveGroupShape $group
                        $null = $nodes.Add(@{
                            id = $group.id
                            label = $group.displayName
                            type = 'group'
                            shape = $groupShape
                            isPIMEnabled = [bool]$group.isPIMEnabled
                            isAssignableToRole = $group.isAssignableToRole
                            securityEnabled = $group.securityEnabled
                        })
                        $nodeIndex[$group.id] = $nodes.Count - 1
                    } else {
                        Write-Verbose "      Group node already exists: $($group.displayName)"
                    }
                    Write-Verbose "      Adding edge: $($group.displayName) -> $($pimAssignment.RoleName)"
                    $null = $edges.Add(@{
                        from = $group.id
                        to = $roleId
                        type = 'has_role'
                        label = $assignmentLabel
                        isPIM = $true
                    })
                }
            }
            'servicePrincipal' {
                $sp = $ServicePrincipals | Where-Object { $_.id -eq $pimAssignment.PrincipalId } | Select-Object -First 1
                if ($sp) {
                    if (-not $nodeIndex.ContainsKey($sp.id)) {
                        $null = $nodes.Add(@{
                            id = $sp.id
                            label = $sp.displayName
                            type = 'servicePrincipal'
                            appId = $sp.appId
                            accountEnabled = $sp.accountEnabled
                        })
                        $nodeIndex[$sp.id] = $nodes.Count - 1
                    }
                    $null = $edges.Add(@{
                        from = $sp.id
                        to = $roleId
                        type = 'has_role'
                        label = $assignmentLabel
                        isPIM = $true
                    })
                }
            }
        }
    }
    
    # Add group membership edges
    foreach ($groupId in $GroupMemberships.Keys) {
        $group = $Groups | Where-Object { $_.id -eq $groupId } | Select-Object -First 1
        if ($group) {
            if (-not $nodeIndex.ContainsKey($group.id)) {
                $groupShape = & $resolveGroupShape $group
                $null = $nodes.Add(@{
                    id = $group.id
                    label = $group.displayName
                    type = 'group'
                    shape = $groupShape
                    isPIMEnabled = [bool]$group.isPIMEnabled
                    isAssignableToRole = $group.isAssignableToRole
                    securityEnabled = $group.securityEnabled
                })
                $nodeIndex[$group.id] = $nodes.Count - 1
            }
            
            foreach ($member in $GroupMemberships[$groupId]) {
                $memberType = if ($member.'@odata.type') { 
                    $member.'@odata.type' -replace '#microsoft.graph.', '' 
                } else { 
                    'unknown' 
                }
                
                # Check if this is a PIM-eligible member (works for both hashtables and PSCustomObjects)
                $isPIMEligible = if ($member -is [hashtable]) {
                    $member.ContainsKey('isPIMEligible') -and $member.isPIMEligible
                } elseif ($member.PSObject.Properties.Name -contains 'isPIMEligible') {
                    $member.isPIMEligible
                } else {
                    $false
                }
                $membershipLabel = if ($isPIMEligible) { 'PIM Eligible' } else { 'Member' }
                
                switch ($memberType) {
                    'user' {
                        $user = $Users | Where-Object { $_.id -eq $member.id } | Select-Object -First 1
                        if ($user) {
                            if (-not $nodeIndex.ContainsKey($user.id)) {
                                $null = $nodes.Add(@{
                                    id = $user.id
                                    label = $user.displayName
                                    type = 'user'
                                    userPrincipalName = $user.userPrincipalName
                                    accountEnabled = $user.accountEnabled
                                })
                                $nodeIndex[$user.id] = $nodes.Count - 1
                            }
                            $null = $edges.Add(@{
                                from = $user.id
                                to = $group.id
                                type = 'member_of'
                                label = $membershipLabel
                                isPIM = $isPIMEligible
                            })
                        }
                    }
                    'group' {
                        $nestedGroup = $Groups | Where-Object { $_.id -eq $member.id } | Select-Object -First 1
                        if ($nestedGroup) {
                            if (-not $nodeIndex.ContainsKey($nestedGroup.id)) {
                                $groupShape = & $resolveGroupShape $nestedGroup
                                $null = $nodes.Add(@{
                                    id = $nestedGroup.id
                                    label = $nestedGroup.displayName
                                    type = 'group'
                                    shape = $groupShape
                                    isPIMEnabled = [bool]$nestedGroup.isPIMEnabled
                                    isAssignableToRole = $nestedGroup.isAssignableToRole
                                    securityEnabled = $nestedGroup.securityEnabled
                                })
                                $nodeIndex[$nestedGroup.id] = $nodes.Count - 1
                            }
                            $null = $edges.Add(@{
                                from = $nestedGroup.id
                                to = $group.id
                                type = 'member_of'
                                label = 'Nested'
                            })
                        }
                    }
                }
            }
        }
    }
    
    # Add group ownership edges
    foreach ($groupId in $GroupOwners.Keys) {
        $group = $Groups | Where-Object { $_.id -eq $groupId } | Select-Object -First 1
        if ($group) {
            if (-not $nodeIndex.ContainsKey($group.id)) {
                $groupShape = & $resolveGroupShape $group
                $null = $nodes.Add(@{
                    id = $group.id
                    label = $group.displayName
                    type = 'group'
                    shape = $groupShape
                    isPIMEnabled = [bool]$group.isPIMEnabled
                    isAssignableToRole = $group.isAssignableToRole
                    securityEnabled = $group.securityEnabled
                })
                $nodeIndex[$group.id] = $nodes.Count - 1
            }
            
            foreach ($owner in $GroupOwners[$groupId]) {
                $user = $Users | Where-Object { $_.id -eq $owner.id } | Select-Object -First 1
                if ($user) {
                    if (-not $nodeIndex.ContainsKey($user.id)) {
                        $null = $nodes.Add(@{
                            id = $user.id
                            label = $user.displayName
                            type = 'user'
                            userPrincipalName = $user.userPrincipalName
                            accountEnabled = $user.accountEnabled
                        })
                        $nodeIndex[$user.id] = $nodes.Count - 1
                    }
                    $null = $edges.Add(@{
                        from = $user.id
                        to = $group.id
                        type = 'owns'
                        label = 'Owner'
                    })
                }
            }
        }
    }
    
    # Add service principal ownership edges
    foreach ($spId in $SPOwners.Keys) {
        $sp = $ServicePrincipals | Where-Object { $_.id -eq $spId } | Select-Object -First 1
        if ($sp) {
            if (-not $nodeIndex.ContainsKey($sp.id)) {
                $null = $nodes.Add(@{
                    id = $sp.id
                    label = $sp.displayName
                    type = 'servicePrincipal'
                    appId = $sp.appId
                    accountEnabled = $sp.accountEnabled
                })
                $nodeIndex[$sp.id] = $nodes.Count - 1
            }
            
            foreach ($owner in $SPOwners[$spId]) {
                $user = $Users | Where-Object { $_.id -eq $owner.id } | Select-Object -First 1
                if ($user) {
                    if (-not $nodeIndex.ContainsKey($user.id)) {
                        $null = $nodes.Add(@{
                            id = $user.id
                            label = $user.displayName
                            type = 'user'
                            userPrincipalName = $user.userPrincipalName
                            accountEnabled = $user.accountEnabled
                        })
                        $nodeIndex[$user.id] = $nodes.Count - 1
                    }
                    $null = $edges.Add(@{
                        from = $user.id
                        to = $sp.id
                        type = 'owns'
                        label = 'Owner'
                    })
                }
            }
        }
    }
    
    # Add service principal app role assignment edges (users/groups assigned to SP)
    foreach ($spId in $SPAppRoleAssignments.Keys) {
        $sp = $ServicePrincipals | Where-Object { $_.id -eq $spId } | Select-Object -First 1
        if ($sp) {
            if (-not $nodeIndex.ContainsKey($sp.id)) {
                $null = $nodes.Add(@{
                    id = $sp.id
                    label = $sp.displayName
                    type = 'servicePrincipal'
                    appId = $sp.appId
                    accountEnabled = $sp.accountEnabled
                })
                $nodeIndex[$sp.id] = $nodes.Count - 1
            }
            
            foreach ($assignment in $SPAppRoleAssignments[$spId]) {
                $principalType = $assignment.principalType
                
                if ($principalType -eq 'User') {
                    $user = $Users | Where-Object { $_.id -eq $assignment.principalId } | Select-Object -First 1
                    if ($user) {
                        if (-not $nodeIndex.ContainsKey($user.id)) {
                            $null = $nodes.Add(@{
                                id = $user.id
                                label = $user.displayName
                                type = 'user'
                                userPrincipalName = $user.userPrincipalName
                                accountEnabled = $user.accountEnabled
                            })
                            $nodeIndex[$user.id] = $nodes.Count - 1
                        }
                        $null = $edges.Add(@{
                            from = $user.id
                            to = $sp.id
                            type = 'assigned_to'
                            label = 'Assigned'
                        })
                    }
                }
                elseif ($principalType -eq 'Group') {
                    $group = $Groups | Where-Object { $_.id -eq $assignment.principalId } | Select-Object -First 1
                    if ($group) {
                        if (-not $nodeIndex.ContainsKey($group.id)) {
                            $groupShape = & $resolveGroupShape $group
                            $null = $nodes.Add(@{
                                id = $group.id
                                label = $group.displayName
                                type = 'group'
                                shape = $groupShape
                                isPIMEnabled = [bool]$group.isPIMEnabled
                                isAssignableToRole = $group.isAssignableToRole
                                securityEnabled = $group.securityEnabled
                            })
                            $nodeIndex[$group.id] = $nodes.Count - 1
                        }
                        $null = $edges.Add(@{
                            from = $group.id
                            to = $sp.id
                            type = 'assigned_to'
                            label = 'Assigned'
                        })
                    }
                }
            }
        }
    }
    
    # Add app registration ownership edges
    foreach ($appId in $AppOwners.Keys) {
        $app = $AppRegistrations | Where-Object { $_.id -eq $appId } | Select-Object -First 1
        if ($app) {
            if (-not $nodeIndex.ContainsKey($app.id)) {
                $null = $nodes.Add(@{
                    id = $app.id
                    label = $app.displayName
                    type = 'application'
                    appId = $app.appId
                })
                $nodeIndex[$app.id] = $nodes.Count - 1
            }
            
            foreach ($owner in $AppOwners[$appId]) {
                $user = $Users | Where-Object { $_.id -eq $owner.id } | Select-Object -First 1
                if ($user) {
                    if (-not $nodeIndex.ContainsKey($user.id)) {
                        $null = $nodes.Add(@{
                            id = $user.id
                            label = $user.displayName
                            type = 'user'
                            userPrincipalName = $user.userPrincipalName
                            accountEnabled = $user.accountEnabled
                        })
                        $nodeIndex[$user.id] = $nodes.Count - 1
                    }
                    $null = $edges.Add(@{
                        from = $user.id
                        to = $app.id
                        type = 'owns'
                        label = 'Owner'
                    })
                }
            }
        }
    }
    
    # Link app registrations to their service principals
    foreach ($app in $AppRegistrations) {
        $sp = $ServicePrincipals | Where-Object { $_.appId -eq $app.appId } | Select-Object -First 1
        if ($sp) {
            if (-not $nodeIndex.ContainsKey($app.id)) {
                $null = $nodes.Add(@{
                    id = $app.id
                    label = $app.displayName
                    type = 'application'
                    appId = $app.appId
                })
                $nodeIndex[$app.id] = $nodes.Count - 1
            }
            if (-not $nodeIndex.ContainsKey($sp.id)) {
                $null = $nodes.Add(@{
                    id = $sp.id
                    label = $sp.displayName
                    type = 'servicePrincipal'
                    appId = $sp.appId
                    accountEnabled = $sp.accountEnabled
                })
                $nodeIndex[$sp.id] = $nodes.Count - 1
            }
            $null = $edges.Add(@{
                from = $app.id
                to = $sp.id
                type = 'has_service_principal'
                label = 'Creates'
            })
        }
    }
    
    # Add "can_manage" edges for administrative roles with app/SP management capabilities
    $appManagementRoles = @(
        'Cloud Application Administrator',
        'Application Administrator',
        'Hybrid Identity Administrator'
    )

    # Find all principals with app management roles (from both direct and PIM)
    $allRoleAssignments = @($RoleAssignments; $PIMAssignments)
    $appAdmins = $allRoleAssignments | Where-Object { $appManagementRoles -contains $_.RoleName }

    foreach ($admin in $appAdmins) {
        $principalId = if ($admin.MemberId) { $admin.MemberId } else { $admin.PrincipalId }

        # Add can_manage edges to all service principals with roles
        foreach ($sp in $ServicePrincipals) {
            $spHasRole = $allRoleAssignments | Where-Object { $_.MemberId -eq $sp.id }
            if ($spHasRole) {
                # Ensure both nodes exist
                if ($nodeIndex.ContainsKey($principalId) -and $nodeIndex.ContainsKey($sp.id)) {
                    $null = $edges.Add(@{
                        from = $principalId
                        to = $sp.id
                        type = 'can_manage'
                        label = 'Can Manage'
                        isPIM = $admin.PSObject.Properties.Name -contains 'AssignmentType'
                    })
                }
            }
        }

        # Add can_manage edges to all app registrations
        foreach ($app in $AppRegistrations) {
            # Only add if app is linked to a privileged SP
            $sp = $ServicePrincipals | Where-Object { $_.appId -eq $app.appId } | Select-Object -First 1
            if ($sp) {
                $spHasRole = $allRoleAssignments | Where-Object { $_.MemberId -eq $sp.id }
                if ($spHasRole) {
                    # Ensure both nodes exist
                    if ($nodeIndex.ContainsKey($principalId) -and $nodeIndex.ContainsKey($app.id)) {
                        $null = $edges.Add(@{
                            from = $principalId
                            to = $app.id
                            type = 'can_manage'
                            label = 'Can Manage'
                            isPIM = $admin.PSObject.Properties.Name -contains 'AssignmentType'
                        })
                    }
                }
            }
        }
    }

    Write-Verbose "Built graph with $($nodes.Count) nodes and $($edges.Count) edges"
    
    # Calculate escalation paths - mark edges that are part of paths to critical high-privilege roles
    Write-Verbose "Calculating escalation paths to critical high-privilege roles..."
    
    # Define critical roles for escalation path analysis (most dangerous)
    $criticalRoles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Application Administrator',
        'Cloud Application Administrator'
    )
    
    $criticalRoleNodes = $nodes | Where-Object { $_.type -eq 'role' -and $criticalRoles -contains $_.label }
    $escalationEdges = [System.Collections.Generic.HashSet[string]]::new()
    
    # Build reverse adjacency list (to -> from) for backtracking
    $reverseAdjacency = @{}
    foreach ($edge in $edges) {
        if (-not $reverseAdjacency.ContainsKey($edge.to)) {
            $reverseAdjacency[$edge.to] = @()
        }
        $reverseAdjacency[$edge.to] += @{
            from = $edge.from
            to = $edge.to
            type = $edge.type
            label = $edge.label
        }
    }
    
    # BFS from each critical role backwards to find all paths
    foreach ($roleNode in $criticalRoleNodes) {
        $visited = @{}
        $queue = [System.Collections.Queue]::new()
        $queue.Enqueue($roleNode.id)
        $visited[$roleNode.id] = $true
        
        while ($queue.Count -gt 0) {
            $currentId = $queue.Dequeue()
            
            if ($reverseAdjacency.ContainsKey($currentId)) {
                foreach ($edgeInfo in $reverseAdjacency[$currentId]) {
                    $edgeKey = "$($edgeInfo.from)->$($edgeInfo.to)"
                    $null = $escalationEdges.Add($edgeKey)
                    
                    if (-not $visited.ContainsKey($edgeInfo.from)) {
                        $visited[$edgeInfo.from] = $true
                        $queue.Enqueue($edgeInfo.from)
                    }
                }
            }
        }
    }
    
    # Mark edges that are part of escalation paths to critical roles
    $edgesWithEscalationMarker = foreach ($edge in $edges) {
        $edgeKey = "$($edge.from)->$($edge.to)"
        $isEscalationPath = $escalationEdges.Contains($edgeKey)
        
        # Create new hashtable with all original properties plus isEscalationPath
        $newEdge = @{
            from = $edge.from
            to = $edge.to
            type = $edge.type
            label = $edge.label
            isEscalationPath = $isEscalationPath
        }
        
        # Copy any additional properties
        if ($edge.ContainsKey('isPIM')) { $newEdge.isPIM = $edge.isPIM }
        
        $newEdge
    }
    
    Write-Verbose "Identified $($escalationEdges.Count) edges that are part of escalation paths to critical roles"
    
    return @{
        nodes = $nodes
        edges = $edgesWithEscalationMarker
        escalationStats = @{
            totalEdges = $edges.Count
            escalationEdges = $escalationEdges.Count
            criticalRoles = $criticalRoleNodes.Count
        }
    }
}
function Get-ScEntraEscalationPaths {
    <#
    .SYNOPSIS
        Analyzes and identifies privilege escalation paths
    
    .DESCRIPTION
        Analyzes nested group memberships, role assignments, and ownership patterns to identify
        potential privilege escalation risks. Uses batch processing to minimize Graph API calls.
    
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
    
    # Hashtables to store membership and ownership data for graph building
    $groupMemberships = @{}
    $groupOwners = @{}
    $spOwners = @{}
    $spAppRoleAssignments = @{}
    $appOwners = @{}
    
    # Identify groups that need detailed analysis (those with roles or PIM assignments)
    $groupsWithRoles = $RoleAssignments | Where-Object { $_.MemberType -eq 'group' } | Select-Object -ExpandProperty MemberId -Unique
    $pimEnabledGroupIds = $Groups | Where-Object { $_.isPIMEnabled -eq $true } | Select-Object -ExpandProperty id -Unique
    $roleEnabledGroups = $Groups | Where-Object { $_.isAssignableToRole -eq $true } | Select-Object -ExpandProperty id
    
    # Combine and deduplicate all relevant group IDs
    $relevantGroupIds = @($groupsWithRoles; $pimEnabledGroupIds; $roleEnabledGroups) | Select-Object -Unique
    
    Write-Host "Found $($roleEnabledGroups.Count) role-assignable groups" -ForegroundColor Yellow
    Write-Host "Found $($pimEnabledGroupIds.Count) PIM-enabled groups" -ForegroundColor Yellow
    Write-Host "Analyzing $($relevantGroupIds.Count) groups with role assignments or PIM eligibility (optimized)" -ForegroundColor Cyan
    
    # Build batch requests for group members, owners, and transitive members
    $batchRequests = @()
    $requestId = 0
    
    foreach ($groupId in $relevantGroupIds) {
        # Members request (with full details for graph building)
        $batchRequests += @{
            id = "$requestId-members-$groupId"
            method = "GET"
            url = "/groups/$groupId/members?`$select=id,displayName,userPrincipalName&`$count=true"
            headers = @{
                "ConsistencyLevel" = "eventual"
            }
        }
        $requestId++
        
        # For PIM-enabled groups, also fetch eligible and active members
        if ($pimEnabledGroupIds -contains $groupId) {
            $batchRequests += @{
                id = "$requestId-pim-eligible-$groupId"
                method = "GET"
                url = "/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$groupId'&`$expand=principal"
            }
            $requestId++
            
            $batchRequests += @{
                id = "$requestId-pim-active-$groupId"
                method = "GET"
                url = "/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$groupId'&`$expand=principal"
            }
            $requestId++
        }
        
        # Owners request (with full details for graph building)
        $batchRequests += @{
            id = "$requestId-owners-$groupId"
            method = "GET"
            url = "/groups/$groupId/owners?`$select=id,displayName,userPrincipalName"
        }
        $requestId++
        
        # Only get transitive members for groups that have role assignments (not just role-enabled)
        if ($groupsWithRoles -contains $groupId) {
            $batchRequests += @{
                id = "$requestId-transitive-$groupId"
                method = "GET"
                url = "/groups/$groupId/transitiveMembers?`$select=id&`$count=true"
                headers = @{
                    "ConsistencyLevel" = "eventual"
                }
            }
            $requestId++
        }
    }
    
    Write-Verbose "Fetching group data using batch requests ($($batchRequests.Count) requests for $($relevantGroupIds.Count) groups)"
    Write-Progress -Activity "Analyzing escalation paths" -Status "Fetching group membership data in batches" -PercentComplete 10 -Id 5
    
    # Execute batch requests
    $batchResponses = @{}
    if ($batchRequests.Count -gt 0) {
        try {
            $batchResponses = Invoke-GraphBatchRequest -Requests $batchRequests
        }
        catch {
            Write-Warning "Batch request failed, falling back to individual requests: $_"
            # Fallback handled below
        }
    }
    
    # Process batch responses and populate membership/ownership data
    foreach ($groupId in $relevantGroupIds) {
        # Extract members from batch responses
        $membersResponseKey = $batchResponses.Keys | Where-Object { $_ -like "*-members-$groupId" } | Select-Object -First 1
        if ($membersResponseKey) {
            $membersResponse = $batchResponses[$membersResponseKey]
            if ($membersResponse -and $membersResponse.status -eq 200 -and $membersResponse.body.value) {
                $groupMemberships[$groupId] = $membersResponse.body.value
            }
        }
        else {
            # Fallback: fetch individually if not in batch
            try {
                $membersUri = "$script:GraphBaseUrl/groups/$groupId/members?`$select=id,displayName,userPrincipalName"
                $membersResult = Invoke-GraphRequest -Uri $membersUri -Method GET -ErrorAction SilentlyContinue
                if ($membersResult.value) {
                    $groupMemberships[$groupId] = $membersResult.value
                }
            }
            catch {
                Write-Verbose "Could not fetch members for group ${groupId}: $($_.Exception.Message)"
            }
        }
        
        # Get active PIM assignments first to identify truly active members
        $activePIMMembers = @()
        $pimActiveKey = $batchResponses.Keys | Where-Object { $_ -like "*-pim-active-$groupId" } | Select-Object -First 1
        if ($pimActiveKey) {
            $pimActiveResponse = $batchResponses[$pimActiveKey]
            if ($pimActiveResponse -and $pimActiveResponse.status -eq 200 -and $pimActiveResponse.body.value) {
                $activePIMMembers = $pimActiveResponse.body.value | Where-Object { $_.principal } | Select-Object -ExpandProperty principal | Select-Object -ExpandProperty id
                Write-Verbose "Found $($activePIMMembers.Count) active PIM members for group $groupId"
            }
        }
        
        # Extract PIM eligible members and mark them appropriately
        $pimEligibleKey = $batchResponses.Keys | Where-Object { $_ -like "*-pim-eligible-$groupId" } | Select-Object -First 1
        if ($pimEligibleKey) {
            $pimEligibleResponse = $batchResponses[$pimEligibleKey]
            if ($pimEligibleResponse -and $pimEligibleResponse.status -eq 200 -and $pimEligibleResponse.body.value) {
                Write-Verbose "Found $($pimEligibleResponse.body.value.Count) PIM eligible members for group $groupId"
                
                # Initialize array if not already present
                if (-not $groupMemberships.ContainsKey($groupId)) {
                    $groupMemberships[$groupId] = @()
                }
                
                # Process eligible members
                foreach ($eligibility in $pimEligibleResponse.body.value) {
                    if ($eligibility.principal -and $eligibility.principal.id) {
                        $principalId = $eligibility.principal.id
                        $isActive = $activePIMMembers -contains $principalId
                        
                        # Check if this member is already in the list (activated members)
                        $existingMember = $groupMemberships[$groupId] | Where-Object { $_.id -eq $principalId } | Select-Object -First 1
                        
                        if ($existingMember) {
                            # Mark as PIM-eligible regardless of active status
                            # Users who activated their eligibility appear in both /members and eligibilitySchedules
                            $existingMember | Add-Member -NotePropertyName 'isPIMEligible' -NotePropertyValue $true -Force
                            $groupName = ($Groups | Where-Object { $_.id -eq $groupId } | Select-Object -First 1).displayName
                            $status = if ($isActive) { "(Active)" } else { "" }
                            Write-Host "  PIM Eligible $status`: $($existingMember.displayName) → $groupName" -ForegroundColor Magenta
                            Write-Verbose "  Marked existing member as PIM eligible: $($existingMember.displayName) (Active: $isActive)"
                        } else {
                            # Add user who is eligible but not yet activated (not in regular /members)
                            $fullUser = $Users | Where-Object { $_.id -eq $principalId } | Select-Object -First 1
                            if ($fullUser) {
                                # Create a member object with the full user data and @odata.type
                                $memberObject = @{
                                    id = $fullUser.id
                                    displayName = $fullUser.displayName
                                    userPrincipalName = $fullUser.userPrincipalName
                                    '@odata.type' = '#microsoft.graph.user'
                                    isPIMEligible = $true
                                }
                                $groupMemberships[$groupId] += $memberObject
                                $groupName = ($Groups | Where-Object { $_.id -eq $groupId } | Select-Object -First 1).displayName
                                Write-Host "  PIM Eligible (Not Activated): $($fullUser.displayName) → $groupName" -ForegroundColor Magenta
                                Write-Verbose "  Added PIM eligible-only member: $($fullUser.displayName)"
                            }
                        }
                    }
                }
            }
        }
        
        # Extract owners from batch responses
        $ownersResponseKey = $batchResponses.Keys | Where-Object { $_ -like "*-owners-$groupId" } | Select-Object -First 1
        if ($ownersResponseKey) {
            $ownersResponse = $batchResponses[$ownersResponseKey]
            if ($ownersResponse -and $ownersResponse.status -eq 200 -and $ownersResponse.body.value) {
                $groupOwners[$groupId] = $ownersResponse.body.value
            }
        }
        else {
            # Fallback: fetch individually if not in batch
            try {
                $ownersUri = "$script:GraphBaseUrl/groups/$groupId/owners?`$select=id,displayName,userPrincipalName"
                $ownersResult = Invoke-GraphRequest -Uri $ownersUri -Method GET -ErrorAction SilentlyContinue
                if ($ownersResult.value) {
                    $groupOwners[$groupId] = $ownersResult.value
                }
            }
            catch {
                Write-Verbose "Could not fetch owners for group ${groupId}: $($_.Exception.Message)"
            }
        }
    }
    
    # Process role-enabled groups with their fetched data
    $groupCount = 0
    $totalGroups = $roleEnabledGroups.Count
    
    foreach ($groupId in $roleEnabledGroups) {
        $groupCount++
        if ($totalGroups -gt 0) {
            $percentComplete = [math]::Round(20 + ($groupCount / $totalGroups) * 30)
            Write-Progress -Activity "Analyzing escalation paths" -Status "Analyzing role-enabled group $groupCount of $totalGroups" -PercentComplete $percentComplete -Id 5
        }
        
        $group = $Groups | Where-Object { $_.id -eq $groupId }
        if (-not $group) { continue }
        
        # Check if this group has role assignments
        $groupRoles = $RoleAssignments | Where-Object { $_.MemberId -eq $groupId }
        
        if ($groupRoles) {
            # Get counts from collected data
            $memberCount = if ($groupMemberships.ContainsKey($groupId)) { $groupMemberships[$groupId].Count } else { 0 }
            $ownerCount = if ($groupOwners.ContainsKey($groupId)) { $groupOwners[$groupId].Count } else { 0 }
            
            foreach ($role in $groupRoles) {
                $risk = [PSCustomObject]@{
                    RiskType = 'RoleEnabledGroup'
                    Severity = 'High'
                    GroupId = $group.id
                    GroupName = $group.displayName
                    RoleName = $role.RoleName
                    MemberCount = $memberCount
                    OwnerCount = $ownerCount
                    Description = "Role-enabled group '$($group.displayName)' has '$($role.RoleName)' role with $memberCount members"
                }
                $escalationRisks += $risk
            }
        }
    }
    
    # 2. Analyze nested group memberships leading to roles
    Write-Verbose "Analyzing nested group memberships..."
    
    $groupCount = 0
    $totalGroups = $groupsWithRoles.Count
    foreach ($groupId in $groupsWithRoles) {
        $groupCount++
        if ($totalGroups -gt 0) {
            $percentComplete = [math]::Round(50 + ($groupCount / $totalGroups) * 20)
            Write-Progress -Activity "Analyzing escalation paths" -Status "Analyzing nested memberships for group $groupCount of $totalGroups" -PercentComplete $percentComplete -Id 5
        }
        
        $group = $Groups | Where-Object { $_.id -eq $groupId }
        if ($group) {
            $directMemberCount = if ($groupMemberships.ContainsKey($groupId)) { $groupMemberships[$groupId].Count } else { 0 }
            $transitiveMemberCount = 0
            
            # Try to get transitive count from batch responses
            $transitiveResponseKey = $batchResponses.Keys | Where-Object { $_ -like "*-transitive-$groupId" } | Select-Object -First 1
            if ($transitiveResponseKey) {
                $transitiveResponse = $batchResponses[$transitiveResponseKey]
                if ($transitiveResponse -and $transitiveResponse.status -eq 200) {
                    $transitiveMemberCount = if ($transitiveResponse.body.'@odata.count') { 
                        $transitiveResponse.body.'@odata.count' 
                    } else { 
                        $transitiveResponse.body.value.Count 
                    }
                }
            }
            else {
                # Fallback: fetch individually
                try {
                    $transitiveUri = "$script:GraphBaseUrl/groups/$groupId/transitiveMembers?`$select=id&`$count=true"
                    $transitiveResult = Invoke-GraphRequest -Uri $transitiveUri -Method GET -ErrorAction SilentlyContinue
                    $transitiveMemberCount = if ($transitiveResult.'@odata.count') { $transitiveResult.'@odata.count' } else { $transitiveResult.value.Count }
                }
                catch {
                    Write-Verbose "Could not fetch transitive members for group ${groupId}: $($_.Exception.Message)"
                }
            }
            
            if ($transitiveMemberCount -gt $directMemberCount) {
                $nestedMemberCount = $transitiveMemberCount - $directMemberCount
                $groupRoles = $RoleAssignments | Where-Object { $_.MemberId -eq $groupId }
                
                foreach ($role in $groupRoles) {
                    $risk = [PSCustomObject]@{
                        RiskType = 'NestedGroupMembership'
                        Severity = 'Medium'
                        GroupId = $group.id
                        GroupName = $group.displayName
                        RoleName = $role.RoleName
                        DirectMembers = $directMemberCount
                        NestedMembers = $nestedMemberCount
                        Description = "Group '$($group.displayName)' with '$($role.RoleName)' has $nestedMemberCount members through nested groups"
                    }
                    $escalationRisks += $risk
                }
            }
        }
    }
    
    # 3. Analyze service principal ownership - batch processing
    Write-Verbose "Analyzing service principal ownership..."
    Write-Progress -Activity "Analyzing escalation paths" -Status "Analyzing service principal ownership" -PercentComplete 70 -Id 5
    
    # Only analyze SPs with role assignments
    $spsWithRoles = $ServicePrincipals | Where-Object { 
        $spId = $_.id
        $RoleAssignments | Where-Object { $_.MemberId -eq $spId }
    }
    
    # Build batch requests for SP owners and app role assignments
    $spBatchRequests = @()
    $spRequestId = 0
    foreach ($sp in $spsWithRoles) {
        # Owners
        $spBatchRequests += @{
            id = "$spRequestId-sp-owners-$($sp.id)"
            method = "GET"
            url = "/servicePrincipals/$($sp.id)/owners?`$select=id,displayName,userPrincipalName"
        }
        $spRequestId++
        
        # App role assignments (users/groups assigned to this SP)
        $spBatchRequests += @{
            id = "$spRequestId-sp-approles-$($sp.id)"
            method = "GET"
            url = "/servicePrincipals/$($sp.id)/appRoleAssignedTo?`$select=principalId,principalDisplayName,principalType&`$top=100"
        }
        $spRequestId++
    }
    
    $spBatchResponses = @{}
    if ($spBatchRequests.Count -gt 0) {
        Write-Verbose "Fetching service principal data using batch requests ($($spBatchRequests.Count) requests)"
        try {
            $spBatchResponses = Invoke-GraphBatchRequest -Requests $spBatchRequests
        }
        catch {
            Write-Verbose "SP batch request failed, will use fallback: $_"
        }
    }
    
    $spCount = 0
    foreach ($sp in $spsWithRoles) {
        $ownerCount = 0
        
        # Try batch response for owners first
        $ownerResponseKey = $spBatchResponses.Keys | Where-Object { $_ -like "*-sp-owners-$($sp.id)" } | Select-Object -First 1
        if ($ownerResponseKey) {
            $ownerResponse = $spBatchResponses[$ownerResponseKey]
            if ($ownerResponse -and $ownerResponse.status -eq 200 -and $ownerResponse.body.value) {
                $spOwners[$sp.id] = $ownerResponse.body.value
                $ownerCount = $ownerResponse.body.value.Count
            }
        }
        else {
            # Fallback for owners
            try {
                $ownersUri = "$script:GraphBaseUrl/servicePrincipals/$($sp.id)/owners?`$select=id,displayName,userPrincipalName"
                $owners = Invoke-GraphRequest -Uri $ownersUri -Method GET -ErrorAction SilentlyContinue
                if ($owners.value) {
                    $spOwners[$sp.id] = $owners.value
                    $ownerCount = $owners.value.Count
                }
            }
            catch {
                Write-Verbose "Could not fetch owners for service principal $($sp.id): $_"
            }
        }
        
        # Try batch response for app role assignments
        $appRoleResponseKey = $spBatchResponses.Keys | Where-Object { $_ -like "*-sp-approles-$($sp.id)" } | Select-Object -First 1
        if ($appRoleResponseKey) {
            $appRoleResponse = $spBatchResponses[$appRoleResponseKey]
            if ($appRoleResponse -and $appRoleResponse.status -eq 200 -and $appRoleResponse.body.value) {
                $spAppRoleAssignments[$sp.id] = $appRoleResponse.body.value
            }
        }
        else {
            # Fallback for app role assignments
            try {
                $appRolesUri = "$script:GraphBaseUrl/servicePrincipals/$($sp.id)/appRoleAssignedTo?`$select=principalId,principalDisplayName,principalType&`$top=100"
                $appRoles = Invoke-GraphRequest -Uri $appRolesUri -Method GET -ErrorAction SilentlyContinue
                if ($appRoles.value) {
                    $spAppRoleAssignments[$sp.id] = $appRoles.value
                }
            }
            catch {
                Write-Verbose "Could not fetch app role assignments for service principal $($sp.id): $_"
            }
        }
        
        if ($ownerCount -gt 0) {
            $spRoles = $RoleAssignments | Where-Object { $_.MemberId -eq $sp.id }
            
            foreach ($role in $spRoles) {
                $risk = [PSCustomObject]@{
                    RiskType = 'ServicePrincipalOwnership'
                    Severity = 'High'
                    ServicePrincipalId = $sp.id
                    ServicePrincipalName = $sp.displayName
                    RoleName = $role.RoleName
                    OwnerCount = $ownerCount
                    Description = "Service Principal '$($sp.displayName)' with '$($role.RoleName)' has $ownerCount owners who could potentially abuse permissions"
                }
                $escalationRisks += $risk
            }
        }
        $spCount++
    }
    
    # 4. Analyze app registration ownership - batch processing
    Write-Verbose "Analyzing app registration ownership..."
    Write-Progress -Activity "Analyzing escalation paths" -Status "Analyzing app registration ownership" -PercentComplete 85 -Id 5
    
    # Build batch requests for app owners
    $appBatchRequests = @()
    $appRequestId = 0
    foreach ($app in $AppRegistrations) {
        $appBatchRequests += @{
            id = "$appRequestId-app-$($app.id)"
            method = "GET"
            url = "/applications/$($app.id)/owners?`$select=id,displayName,userPrincipalName"
        }
        $appRequestId++
    }
    
    $appBatchResponses = @{}
    if ($appBatchRequests.Count -gt 0) {
        Write-Verbose "Fetching app registration owners using batch requests ($($appBatchRequests.Count) requests)"
        try {
            $appBatchResponses = Invoke-GraphBatchRequest -Requests $appBatchRequests
        }
        catch {
            Write-Verbose "App batch request failed, will use fallback: $_"
        }
    }
    
    $appCount = 0
    foreach ($app in $AppRegistrations) {
        $ownerCount = 0
        
        # Try batch response first
        $ownerResponseKey = $appBatchResponses.Keys | Where-Object { $_ -like "*-app-$($app.id)" } | Select-Object -First 1
        if ($ownerResponseKey) {
            $ownerResponse = $appBatchResponses[$ownerResponseKey]
            if ($ownerResponse -and $ownerResponse.status -eq 200 -and $ownerResponse.body.value) {
                $appOwners[$app.id] = $ownerResponse.body.value
                $ownerCount = $ownerResponse.body.value.Count
            }
        }
        else {
            # Fallback
            try {
                $ownersUri = "$script:GraphBaseUrl/applications/$($app.id)/owners?`$select=id,displayName,userPrincipalName"
                $owners = Invoke-GraphRequest -Uri $ownersUri -Method GET -ErrorAction SilentlyContinue
                if ($owners.value) {
                    $appOwners[$app.id] = $owners.value
                    $ownerCount = $owners.value.Count
                }
            }
            catch {
                Write-Verbose "Could not analyze app registration $($app.id): $_"
            }
        }
        
        if ($ownerCount -gt 5) {
            $risk = [PSCustomObject]@{
                RiskType = 'AppRegistrationOwnership'
                Severity = 'Medium'
                AppId = $app.id
                AppName = $app.displayName
                OwnerCount = $ownerCount
                Description = "App Registration '$($app.displayName)' has $ownerCount owners - potential for credential abuse"
            }
            $escalationRisks += $risk
        }
        $appCount++
    }
    
    Write-Progress -Activity "Analyzing escalation paths" -Completed -Id 5
    
    # 5. Analyze administrative roles with app/SP management capabilities
    Write-Verbose "Analyzing administrative roles with escalation capabilities..."

    # Define roles that can manage applications and service principals
    $appManagementRoles = @(
        'Cloud Application Administrator',
        'Application Administrator',
        'Hybrid Identity Administrator'
    )

    # Define roles that can manage all roles
    $roleManagementRoles = @(
        'Privileged Role Administrator',
        'Global Administrator'
    )

    # Check for users/groups with app management roles who could escalate via SPs
    $appAdminAssignments = $RoleAssignments | Where-Object { $appManagementRoles -contains $_.RoleName }
    $appAdminPIMAssignments = $PIMAssignments | Where-Object { $appManagementRoles -contains $_.RoleName }

    foreach ($assignment in ($appAdminAssignments + $appAdminPIMAssignments)) {
        # Count how many privileged SPs exist that this admin could abuse
        $privilegedSPs = $ServicePrincipals | Where-Object {
            $spId = $_.id
            ($RoleAssignments | Where-Object { $_.MemberId -eq $spId }).Count -gt 0
        }

        if ($privilegedSPs.Count -gt 0) {
            $isPIM = $assignment -in $appAdminPIMAssignments
            $risk = [PSCustomObject]@{
                RiskType = 'AppAdministratorEscalation'
                Severity = 'High'
                PrincipalId = $assignment.MemberId
                PrincipalType = $assignment.MemberType
                RoleName = $assignment.RoleName
                PrivilegedSPCount = $privilegedSPs.Count
                IsPIM = $isPIM
                Description = "$(if($isPIM){'PIM eligible '})$($assignment.RoleName) can manage $($privilegedSPs.Count) service principal(s) with privileged role assignments, enabling potential privilege escalation"
            }
            $escalationRisks += $risk
        }
    }

    # Check for users/groups with role management capabilities
    $roleAdminAssignments = $RoleAssignments | Where-Object { $roleManagementRoles -contains $_.RoleName }
    $roleAdminPIMAssignments = $PIMAssignments | Where-Object { $roleManagementRoles -contains $_.RoleName }

    foreach ($assignment in ($roleAdminAssignments + $roleAdminPIMAssignments)) {
        $isPIM = $assignment -in $roleAdminPIMAssignments

        # These are always high risk as they can assign any role
        $risk = [PSCustomObject]@{
            RiskType = 'RoleAdministratorEscalation'
            Severity = 'Critical'
            PrincipalId = $assignment.MemberId
            PrincipalType = $assignment.MemberType
            RoleName = $assignment.RoleName
            IsPIM = $isPIM
            Description = "$(if($isPIM){'PIM eligible '})$($assignment.RoleName) can assign any role including Global Administrator, representing maximum escalation risk"
        }
        $escalationRisks += $risk
    }

    # 6. Analyze PIM assignments for unusual patterns
    if ($PIMAssignments.Count -gt 0) {
        Write-Verbose "Analyzing PIM assignment patterns..."
        Write-Progress -Activity "Analyzing PIM assignment patterns" -Status "Grouping PIM assignments by principal" -PercentComplete 50 -Id 9
        
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
        
        Write-Progress -Activity "Analyzing PIM assignment patterns" -Completed -Id 9
    }
    
    Write-Host "Identified $($escalationRisks.Count) potential escalation risks" -ForegroundColor Yellow
    
    # Build graph data structure for visualization
    Write-Verbose "Building graph data structure for visualization..."
    Write-Progress -Activity "Analyzing escalation paths" -Status "Building graph visualization data" -PercentComplete 95 -Id 5
    
    # Combine all role assignments (direct + PIM) for graph building
    $allRoleAssignments = @($RoleAssignments; $PIMAssignments)
    
    $graphData = New-ScEntraGraphData `
        -Users $Users `
        -Groups $Groups `
        -ServicePrincipals $ServicePrincipals `
        -AppRegistrations $AppRegistrations `
        -RoleAssignments $RoleAssignments `
        -PIMAssignments $PIMAssignments `
        -GroupMemberships $groupMemberships `
        -GroupOwners $groupOwners `
        -SPOwners $spOwners `
        -SPAppRoleAssignments $spAppRoleAssignments `
        -AppOwners $appOwners
    
    Write-Progress -Activity "Analyzing escalation paths" -Completed -Id 5
    
    return @{
        Risks = $escalationRisks
        GraphData = $graphData
    }
}

#endregion

#region Reporting Functions
# Reporting functions live under Public/Export-ScEntraReport.ps1 with supporting Private helpers.
#endregion

#region Main Analysis Function
# Main analysis orchestrator lives under Public/Invoke-ScEntraAnalysis.ps1
#endregion

# Export module members
Export-ModuleMember -Function @(
    'Connect-ScEntraGraph'
    'Invoke-ScEntraAnalysis'
    'Get-ScEntraUsers'
    'Get-ScEntraGroups'
    'Get-ScEntraServicePrincipals'
    'Get-ScEntraAppRegistrations'
    'Get-ScEntraRoleAssignments'
    'Get-ScEntraPIMAssignments'
    'Get-ScEntraEscalationPaths'
    'New-ScEntraGraphData'
    'Export-ScEntraReport'
)
