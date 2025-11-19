#Requires -Version 7.0

<#
.SYNOPSIS
    ScEntra - Scan Entra for risk in role assignments and escalation paths

.DESCRIPTION
    This module provides functions to inventory Entra ID objects (users, groups, service principals, app registrations)
    and analyze privilege escalation risks through role assignments, PIM, and nested group memberships.
    
    This module uses direct Microsoft Graph REST API endpoints for maximum compatibility and control.
#>

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
            "RoleAssignmentSchedule.Read.Directory"
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
                $script:GraphAccessToken = $token.Token
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
        $uri = "$script:GraphBaseUrl/users?`$select=$select"
        
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
        $uri = "$script:GraphBaseUrl/groups?`$select=$select"
        
        $groups = Get-AllGraphItems -Uri $uri -ProgressActivity "Retrieving groups from Entra ID"
        
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
        $uri = "$script:GraphBaseUrl/servicePrincipals?`$select=$select"
        
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
        $uri = "$script:GraphBaseUrl/applications?`$select=$select"
        
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
    
    # Add role nodes (only for roles that have assignments)
    $assignedRoles = @($RoleAssignments | Select-Object -ExpandProperty RoleName -Unique)
    $pimRoles = @($PIMAssignments | Select-Object -ExpandProperty RoleName -Unique)
    $allRoles = @($assignedRoles; $pimRoles) | Select-Object -Unique
    
    foreach ($roleName in $allRoles) {
        $roleId = "role-$roleName"
        if (-not $nodeIndex.ContainsKey($roleId)) {
            $null = $nodes.Add(@{
                id = $roleId
                label = $roleName
                type = 'role'
                isPrivileged = $true
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
                        $null = $nodes.Add(@{
                            id = $group.id
                            label = $group.displayName
                            type = 'group'
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
    foreach ($pimAssignment in $PIMAssignments) {
        $roleId = "role-$($pimAssignment.RoleName)"
        $assignmentLabel = if ($pimAssignment.AssignmentType -eq 'PIM-Eligible') { 'Eligible' } else { 'PIM Active' }
        
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
                if ($group) {
                    if (-not $nodeIndex.ContainsKey($group.id)) {
                        $null = $nodes.Add(@{
                            id = $group.id
                            label = $group.displayName
                            type = 'group'
                            isAssignableToRole = $group.isAssignableToRole
                            securityEnabled = $group.securityEnabled
                        })
                        $nodeIndex[$group.id] = $nodes.Count - 1
                    }
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
                $null = $nodes.Add(@{
                    id = $group.id
                    label = $group.displayName
                    type = 'group'
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
                                label = 'Member'
                            })
                        }
                    }
                    'group' {
                        $nestedGroup = $Groups | Where-Object { $_.id -eq $member.id } | Select-Object -First 1
                        if ($nestedGroup) {
                            if (-not $nodeIndex.ContainsKey($nestedGroup.id)) {
                                $null = $nodes.Add(@{
                                    id = $nestedGroup.id
                                    label = $nestedGroup.displayName
                                    type = 'group'
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
                $null = $nodes.Add(@{
                    id = $group.id
                    label = $group.displayName
                    type = 'group'
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
                            $null = $nodes.Add(@{
                                id = $group.id
                                label = $group.displayName
                                type = 'group'
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
    
    return @{
        nodes = $nodes
        edges = $edges
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
    $groupsInPIM = $PIMAssignments | Where-Object { $_.PrincipalType -eq 'group' } | Select-Object -ExpandProperty PrincipalId -Unique
    $roleEnabledGroups = $Groups | Where-Object { $_.isAssignableToRole -eq $true } | Select-Object -ExpandProperty id
    
    # Combine and deduplicate all relevant group IDs
    $relevantGroupIds = @($groupsWithRoles; $groupsInPIM; $roleEnabledGroups) | Select-Object -Unique
    
    Write-Host "Found $($roleEnabledGroups.Count) role-enabled groups" -ForegroundColor Yellow
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
        [hashtable]$GraphData = $null,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "./ScEntra-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    )
    
    Write-Verbose "Generating HTML report..."
    
    # Prepare statistics
    $stats = @{
        TotalUsers = $Users.Count
        EnabledUsers = ($Users | Where-Object { $_.accountEnabled -eq $true }).Count
        TotalGroups = $Groups.Count
        RoleEnabledGroups = ($Groups | Where-Object { $_.isAssignableToRole -eq $true }).Count
        SecurityGroups = ($Groups | Where-Object { $_.securityEnabled -eq $true }).Count
        TotalServicePrincipals = $ServicePrincipals.Count
        EnabledServicePrincipals = ($ServicePrincipals | Where-Object { $_.accountEnabled -eq $true }).Count
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
    <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.6/dist/vis-network.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/vis-network@9.1.6/dist/dist/vis-network.min.css" rel="stylesheet" type="text/css" />
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
        
        #escalationGraph {
            width: 100%;
            height: 800px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background: #fafafa;
        }
        
        .graph-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            border: 2px solid #333;
        }
        
        .legend-color.user { background: #4CAF50; }
        .legend-color.group { background: #2196F3; }
        .legend-color.role { background: #FF5722; }
        .legend-color.servicePrincipal { background: #9C27B0; }
        .legend-color.application { background: #FF9800; }
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

    # Add graph visualization if graph data is available
    if ($GraphData -and $GraphData.nodes -and $GraphData.nodes.Count -gt 0) {
        $nodesJson = $GraphData.nodes | ConvertTo-Json -Compress -Depth 10
        $edgesJson = $GraphData.edges | ConvertTo-Json -Compress -Depth 10
        
        $html += @"
        
        <div class="section">
            <h2>🕸️ Escalation Path Graph</h2>
            <p style="margin-bottom: 20px; color: #666;">Interactive graph showing relationships between users, groups, service principals, app registrations, and role assignments. Click on a node to highlight its escalation path.</p>
            
            <div style="margin-bottom: 20px; display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
                <div style="flex: 1; min-width: 300px;">
                    <label for="nodeFilter" style="font-weight: 600; margin-right: 10px;">Filter by entity:</label>
                    <input type="text" id="nodeFilter" placeholder="Search by name..." style="padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; width: 100%; max-width: 400px; font-size: 14px;">
                </div>
                <div>
                    <label for="typeFilter" style="font-weight: 600; margin-right: 10px;">Type:</label>
                    <select id="typeFilter" style="padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                        <option value="">All Types</option>
                        <option value="user">Users</option>
                        <option value="group">Groups</option>
                        <option value="role">Roles</option>
                        <option value="servicePrincipal">Service Principals</option>
                        <option value="application">Applications</option>
                    </select>
                </div>
                <button id="resetGraph" style="padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; font-weight: 600;">Reset View</button>
            </div>
            
            <div id="selectedNodeInfo" style="display: none; margin-bottom: 15px; padding: 12px; background: #f8f9fa; border-left: 4px solid #667eea; border-radius: 4px;">
                <strong>Selected:</strong> <span id="selectedNodeName"></span> <span id="selectedNodeType" style="color: #666; font-size: 0.9em;"></span>
            </div>
            
            <div id="escalationGraph"></div>
            <div class="graph-legend">
                <div class="legend-item">
                    <div class="legend-color user"></div>
                    <span>User</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color group"></div>
                    <span>Group</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color role"></div>
                    <span>Role</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color servicePrincipal"></div>
                    <span>Service Principal</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color application"></div>
                    <span>Application</span>
                </div>
            </div>
        </div>
"@
    }

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
            
            # Extract entity IDs from risk for filtering
            $entityIds = @()
            if ($risk.GroupId) { $entityIds += $risk.GroupId }
            if ($risk.ServicePrincipalId) { $entityIds += $risk.ServicePrincipalId }
            if ($risk.AppId) { $entityIds += $risk.AppId }
            if ($risk.PrincipalId) { $entityIds += $risk.PrincipalId }
            if ($risk.MemberId) { $entityIds += $risk.MemberId }
            $entityIdsAttr = ($entityIds -join ',')
            
            $html += @"
                    <tr data-entity-ids="$entityIdsAttr" class="risk-row">
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
"@

    # Add graph visualization script if graph data is available
    if ($GraphData -and $GraphData.nodes -and $GraphData.nodes.Count -gt 0) {
        $html += @"
    <script>
        // Escalation Path Graph
        const graphNodes = $nodesJson;
        const graphEdges = $edgesJson;
        
        // Transform nodes for vis-network
        const nodes = new vis.DataSet(graphNodes.map(node => ({
            id: node.id,
            label: node.label,
            group: node.type,
            title: node.label + ' (' + node.type + ')',
            shape: node.type === 'role' ? 'diamond' : (node.type === 'group' ? 'box' : 'dot'),
            color: {
                background: node.type === 'user' ? '#4CAF50' : 
                           node.type === 'group' ? '#2196F3' :
                           node.type === 'role' ? '#FF5722' :
                           node.type === 'servicePrincipal' ? '#9C27B0' :
                           node.type === 'application' ? '#FF9800' : '#999',
                border: '#333'
            },
            font: { color: '#333', size: 14 }
        })));
        
        // Transform edges for vis-network
        const edges = new vis.DataSet(graphEdges.map((edge, idx) => ({
            id: edge.from + '-' + edge.to + '-' + idx,
            from: edge.from,
            to: edge.to,
            label: edge.label || edge.type,
            arrows: 'to',
            color: {
                color: edge.type === 'has_role' ? '#FF5722' :
                       edge.type === 'member_of' ? '#2196F3' :
                       edge.type === 'owns' ? '#FF9800' :
                       edge.type === 'assigned_to' ? '#00BCD4' :
                       edge.type === 'can_manage' ? '#E91E63' :
                       edge.isPIM ? '#9C27B0' : '#999',
                opacity: 0.7
            },
            dashes: edge.isPIM || edge.type === 'owns' || edge.type === 'can_manage',
            width: edge.type === 'has_role' ? 3 : (edge.type === 'can_manage' ? 2 : 1.5),
            font: { size: 10, color: '#666', align: 'middle' },
            edgeType: edge.type,
            isPIM: edge.isPIM || false
        })));
        
        const container = document.getElementById('escalationGraph');
        const data = { nodes: nodes, edges: edges };
        
        const options = {
            nodes: {
                borderWidth: 2,
                size: 25,
                font: {
                    size: 14,
                    color: '#333'
                },
                scaling: {
                    min: 20,
                    max: 40
                }
            },
            edges: {
                smooth: {
                    type: 'continuous',
                    roundness: 0.5
                },
                width: 2
            },
            physics: {
                enabled: true,
                barnesHut: {
                    gravitationalConstant: -8000,
                    centralGravity: 0.3,
                    springLength: 200,
                    springConstant: 0.04,
                    damping: 0.09,
                    avoidOverlap: 0.1
                },
                stabilization: {
                    enabled: true,
                    iterations: 200,
                    updateInterval: 25
                }
            },
            interaction: {
                hover: true,
                tooltipDelay: 100,
                zoomView: true,
                dragView: true
            },
            layout: {
                improvedLayout: true,
                hierarchical: {
                    enabled: false
                }
            }
        };
        
        const network = new vis.Network(container, data, options);
        
        // Disable physics after stabilization to stop movement
        network.once('stabilizationIterationsDone', function() {
            network.setOptions({ physics: false });
        });
        
        // Store original node colors for reset
        const originalNodeColors = {};
        graphNodes.forEach(node => {
            originalNodeColors[node.id] = {
                background: node.type === 'user' ? '#4CAF50' : 
                           node.type === 'group' ? '#2196F3' :
                           node.type === 'role' ? '#FF5722' :
                           node.type === 'servicePrincipal' ? '#9C27B0' :
                           node.type === 'application' ? '#FF9800' : '#999',
                border: '#333'
            };
        });
        
        // Function to get all connected nodes (directly or through path)
        function getConnectedNodes(nodeId, visited = new Set()) {
            if (visited.has(nodeId)) return visited;
            visited.add(nodeId);
            
            // Get all directly connected nodes via edges
            const directlyConnected = network.getConnectedNodes(nodeId);
            directlyConnected.forEach(connId => {
                if (!visited.has(connId)) {
                    getConnectedNodes(connId, visited);
                }
            });
            
            return visited;
        }
        
        // Function to highlight escalation path
        function highlightPath(nodeId) {
            const pathNodes = getConnectedNodes(nodeId);
            const pathEdges = new Set();
            
            // Find all edges in the path
            pathNodes.forEach(nId => {
                const connEdges = network.getConnectedEdges(nId);
                connEdges.forEach(edgeId => {
                    const edge = edges.get(edgeId);
                    if (edge && pathNodes.has(edge.from) && pathNodes.has(edge.to)) {
                        pathEdges.add(edgeId);
                    }
                });
            });
            
            // Hide nodes not in path, show nodes in path
            const updates = [];
            nodes.forEach(node => {
                if (pathNodes.has(node.id)) {
                    // Highlighted nodes - shown
                    updates.push({
                        id: node.id,
                        color: {
                            background: originalNodeColors[node.id].background,
                            border: '#000',
                            highlight: {
                                background: originalNodeColors[node.id].background,
                                border: '#000'
                            }
                        },
                        borderWidth: 4,
                        font: { color: '#000', size: 16, bold: true },
                        hidden: false
                    });
                } else {
                    // Hide unrelated nodes
                    updates.push({
                        id: node.id,
                        hidden: true
                    });
                }
            });
            nodes.update(updates);
            
            // Show edges in path with different styling based on type
            const edgeUpdates = [];
            edges.forEach(edge => {
                if (pathEdges.has(edge.id)) {
                    // In path - show but style differently based on edge type
                    if (edge.edgeType === 'has_role') {
                        // Show role assignment edges but muted (light gray, thin)
                        edgeUpdates.push({
                            id: edge.id,
                            width: 1,
                            color: { color: '#ddd', opacity: 0.4 },
                            hidden: false,
                            dashes: true
                        });
                    } else {
                        // Show relationship edges with emphasis (dark gray, thick)
                        edgeUpdates.push({
                            id: edge.id,
                            width: 3,
                            color: { color: '#666', opacity: 1 },
                            hidden: false
                        });
                    }
                } else {
                    // Hide unrelated edges
                    edgeUpdates.push({
                        id: edge.id,
                        hidden: true
                    });
                }
            });
            edges.update(edgeUpdates);
            
            // Filter risk table to show only related risks
            filterRiskTable(Array.from(pathNodes));
        }
        
        // Function to filter risk table based on selected nodes
        function filterRiskTable(nodeIds) {
            const riskRows = document.querySelectorAll('.risk-row');
            let visibleCount = 0;
            
            riskRows.forEach(row => {
                const entityIds = row.getAttribute('data-entity-ids');
                if (!entityIds) {
                    row.style.display = '';
                    visibleCount++;
                    return;
                }
                
                const rowEntityIds = entityIds.split(',').filter(id => id.trim());
                const hasMatch = rowEntityIds.some(entityId => nodeIds.includes(entityId));
                
                if (hasMatch) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            // Show message if no risks match
            const risksSection = document.querySelector('.section h2');
            if (risksSection && risksSection.textContent.includes('Escalation Risks')) {
                const existingMsg = document.getElementById('risk-filter-msg');
                if (existingMsg) existingMsg.remove();
                
                if (visibleCount === 0 && riskRows.length > 0) {
                    const msg = document.createElement('p');
                    msg.id = 'risk-filter-msg';
                    msg.style.cssText = 'color: #666; font-style: italic; margin-top: 10px;';
                    msg.textContent = 'No escalation risks found for the selected entity.';
                    risksSection.parentNode.insertBefore(msg, risksSection.nextSibling);
                }
            }
        }
        
        // Function to reset highlighting
        function resetHighlight() {
            const updates = [];
            graphNodes.forEach(node => {
                updates.push({
                    id: node.id,
                    color: originalNodeColors[node.id],
                    borderWidth: 2,
                    font: { color: '#333', size: 14 },
                    hidden: false
                });
            });
            nodes.update(updates);
            
            const edgeUpdates = [];
            edges.forEach(edge => {
                edgeUpdates.push({
                    id: edge.id,
                    width: edge.edgeType === 'has_role' ? 3 : (edge.edgeType === 'can_manage' ? 2 : 1.5),
                    color: {
                        color: edge.edgeType === 'has_role' ? '#FF5722' :
                               edge.edgeType === 'member_of' ? '#2196F3' :
                               edge.edgeType === 'owns' ? '#FF9800' :
                               edge.edgeType === 'assigned_to' ? '#00BCD4' :
                               edge.edgeType === 'can_manage' ? '#E91E63' :
                               edge.isPIM ? '#9C27B0' : '#999',
                        opacity: 0.7
                    },
                    hidden: false
                });
            });
            edges.update(edgeUpdates);
            
            document.getElementById('selectedNodeInfo').style.display = 'none';
            
            // Reset risk table
            const riskRows = document.querySelectorAll('.risk-row');
            riskRows.forEach(row => {
                row.style.display = '';
            });
            const riskMsg = document.getElementById('risk-filter-msg');
            if (riskMsg) riskMsg.remove();
        }
        
        // Click handler to highlight path
        network.on('click', function(params) {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                const node = nodes.get(nodeId);
                
                highlightPath(nodeId);
                
                // Show selected node info
                document.getElementById('selectedNodeName').textContent = node.label;
                document.getElementById('selectedNodeType').textContent = '(' + node.type + ')';
                document.getElementById('selectedNodeInfo').style.display = 'block';
                
                // Focus on the selected node
                network.focus(nodeId, {
                    scale: 1.5,
                    animation: {
                        duration: 500,
                        easingFunction: 'easeInOutQuad'
                    }
                });
            } else {
                resetHighlight();
            }
        });
        
        // Filter functionality
        document.getElementById('nodeFilter').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const typeFilter = document.getElementById('typeFilter').value;
            
            const matchingNodes = graphNodes.filter(node => {
                const matchesSearch = !searchTerm || node.label.toLowerCase().includes(searchTerm);
                const matchesType = !typeFilter || node.type === typeFilter;
                return matchesSearch && matchesType;
            });
            
            if (matchingNodes.length === 1) {
                network.selectNodes([matchingNodes[0].id]);
                network.focus(matchingNodes[0].id, {
                    scale: 1.5,
                    animation: { duration: 500, easingFunction: 'easeInOutQuad' }
                });
                highlightPath(matchingNodes[0].id);
                
                document.getElementById('selectedNodeName').textContent = matchingNodes[0].label;
                document.getElementById('selectedNodeType').textContent = '(' + matchingNodes[0].type + ')';
                document.getElementById('selectedNodeInfo').style.display = 'block';
            } else if (matchingNodes.length > 1) {
                // Show only matching nodes
                const matchingIds = new Set(matchingNodes.map(n => n.id));
                const updates = [];
                nodes.forEach(node => {
                    if (matchingIds.has(node.id)) {
                        updates.push({
                            id: node.id,
                            color: originalNodeColors[node.id],
                            borderWidth: 4,
                            font: { color: '#000', size: 16 },
                            hidden: false
                        });
                    } else {
                        updates.push({
                            id: node.id,
                            hidden: true
                        });
                    }
                });
                nodes.update(updates);
            } else if (searchTerm || typeFilter) {
                // No matches - hide everything
                const updates = [];
                nodes.forEach(node => {
                    updates.push({
                        id: node.id,
                        hidden: true
                    });
                });
                nodes.update(updates);
            } else {
                resetHighlight();
            }
        });
        
        document.getElementById('typeFilter').addEventListener('change', function() {
            document.getElementById('nodeFilter').dispatchEvent(new Event('input'));
        });
        
        // Reset button
        document.getElementById('resetGraph').addEventListener('click', function() {
            document.getElementById('nodeFilter').value = '';
            document.getElementById('typeFilter').value = '';
            resetHighlight();
            network.fit({
                animation: {
                    duration: 500,
                    easingFunction: 'easeInOutQuad'
                }
            });
        });
    </script>
"@
    }
    
    $html += @"
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
            Users = $Users | Select-Object id, displayName, userPrincipalName, accountEnabled, userType
            Groups = $Groups | Select-Object id, displayName, isAssignableToRole, securityEnabled, memberCount
            ServicePrincipals = $ServicePrincipals | Select-Object id, displayName, appId, accountEnabled
            AppRegistrations = $AppRegistrations | Select-Object id, displayName, appId
            RoleAssignments = $RoleAssignments
            PIMAssignments = $PIMAssignments
            EscalationRisks = $EscalationRisks
            GraphData = $GraphData
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
        # First authenticate using Azure PowerShell or Azure CLI
        # Connect-AzAccount  # or: az login
        Invoke-ScEntraAnalysis
        
    .EXAMPLE
        Invoke-ScEntraAnalysis -OutputPath "C:\Reports\entra-report.html"
        
    .EXAMPLE
        # Use with an existing access token
        Connect-ScEntraGraph -AccessToken "eyJ0..."
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
        if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
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
            
            $connected = Connect-ScEntraGraph -Scopes $requiredScopes
            if (-not $connected) {
                Write-Error "Failed to connect to Microsoft Graph. Please authenticate using Azure PowerShell (Connect-AzAccount) or Azure CLI (az login) first."
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
    
    $escalationResult = Get-ScEntraEscalationPaths `
        -Users $users `
        -Groups $groups `
        -RoleAssignments $roleAssignments `
        -PIMAssignments $pimAssignments `
        -ServicePrincipals $servicePrincipals `
        -AppRegistrations $appRegistrations
    
    # Extract risks and graph data from result
    $escalationRisks = $escalationResult.Risks
    $graphData = $escalationResult.GraphData
    
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
        -GraphData $graphData `
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
        GraphData = $graphData
        ReportPath = $reportPath
    }
}

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
    'Export-ScEntraReport'
)
