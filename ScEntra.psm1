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
                        $null = $nodes.Add(@{
                            id = $group.id
                            label = $group.displayName
                            type = 'group'
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
        
        # For PIM-enabled groups, also fetch eligible members
        if ($groupsInPIM -contains $groupId) {
            $batchRequests += @{
                id = "$requestId-pim-eligible-$groupId"
                method = "GET"
                url = "/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$groupId'&`$expand=principal"
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
        
        # Extract PIM eligible members and add to group memberships
        $pimEligibleKey = $batchResponses.Keys | Where-Object { $_ -like "*-pim-eligible-$groupId" } | Select-Object -First 1
        if ($pimEligibleKey) {
            $pimEligibleResponse = $batchResponses[$pimEligibleKey]
            if ($pimEligibleResponse -and $pimEligibleResponse.status -eq 200 -and $pimEligibleResponse.body.value) {
                Write-Verbose "Found $($pimEligibleResponse.body.value.Count) PIM eligible members for group $groupId"
                
                # Initialize array if not already present
                if (-not $groupMemberships.ContainsKey($groupId)) {
                    $groupMemberships[$groupId] = @()
                }
                
                # Add eligible members (with principal info from expanded query)
                foreach ($eligibility in $pimEligibleResponse.body.value) {
                    if ($eligibility.principal -and $eligibility.principal.id) {
                        # Check if this member is already in the list (to avoid duplicates)
                        $existingMember = $groupMemberships[$groupId] | Where-Object { $_.id -eq $eligibility.principal.id } | Select-Object -First 1
                        if (-not $existingMember) {
                            # Look up the full user object from the Users collection
                            $fullUser = $Users | Where-Object { $_.id -eq $eligibility.principal.id } | Select-Object -First 1
                            if ($fullUser) {
                                # Create a member object with the full user data and @odata.type
                                $memberObject = @{
                                    id = $fullUser.id
                                    displayName = $fullUser.displayName
                                    userPrincipalName = $fullUser.userPrincipalName
                                    '@odata.type' = '#microsoft.graph.user'
                                }
                                $groupMemberships[$groupId] += $memberObject
                                Write-Verbose "  Added PIM eligible member: $($fullUser.displayName)"
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
        
        .graph-controls {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 15px;
            padding: 10px;
        }
        
        .control-btn {
            padding: 10px 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: background 0.2s;
        }
        
        .control-btn:hover {
            background: #5568d3;
        }
        
        .control-btn:active {
            transform: scale(0.95);
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .legend-icon {
            width: 22px;
            height: 22px;
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
                <div>
                    <label for="assignmentFilter" style="font-weight: 600; margin-right: 10px;">Assignment:</label>
                    <select id="assignmentFilter" style="padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                        <option value="">All Assignments</option>
                        <option value="member">Member</option>
                        <option value="active">Active</option>
                        <option value="eligible">Eligible</option>
                    </select>
                </div>
                <button id="resetGraph" style="padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; font-weight: 600;">Reset View</button>
            </div>
            
            <div id="selectedNodeInfo" style="display: none; margin-bottom: 15px; padding: 12px; background: #f8f9fa; border-left: 4px solid #667eea; border-radius: 4px;">
                <strong>Selected:</strong> <span id="selectedNodeName"></span> <span id="selectedNodeType" style="color: #666; font-size: 0.9em;"></span>
            </div>
            
            <div id="escalationGraph"></div>
            
            <div class="graph-controls">
                <button id="zoomIn" class="control-btn" title="Zoom In">🔍+</button>
                <button id="zoomOut" class="control-btn" title="Zoom Out">🔍−</button>
                <button id="fitGraph" class="control-btn" title="Fit to Screen">⊡</button>
                <button id="resetView" class="control-btn" title="Reset View">↻</button>
            </div>
            
            <div class="graph-legend">
                <div class="legend-item">
                    <img class="legend-icon" data-icon-type="user" alt="User icon" />
                    <span>User</span>
                </div>
                <div class="legend-item">
                    <img class="legend-icon" data-icon-type="group" alt="Group icon" />
                    <span>Group</span>
                </div>
                <div class="legend-item">
                    <img class="legend-icon" data-icon-type="role" alt="Role icon" />
                    <span>Role</span>
                </div>
                <div class="legend-item">
                    <img class="legend-icon" data-icon-type="servicePrincipal" alt="Service principal icon" />
                    <span>Service Principal</span>
                </div>
                <div class="legend-item">
                    <img class="legend-icon" data-icon-type="application" alt="Application icon" />
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
        
        // Helper to create data URIs for inline SVG icons
        const svgIcon = function(svg) { return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg); };
        const defaultUserIconSvg = '<svg id="e24671f6-f501-4952-a2db-8b0b1d329c17" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="be92901b-ec33-4c65-adf1-9b0eed06d677" x1="9" y1="6.88" x2="9" y2="20.45" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient><linearGradient id="b46fc246-25d8-4398-8779-1042e8cacae7" x1="8.61" y1="-0.4" x2="9.6" y2="11.92" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient></defs><title>Icon-identity-230</title><path d="M15.72,18a1.45,1.45,0,0,0,1.45-1.45.47.47,0,0,0,0-.17C16.59,11.81,14,8.09,9,8.09S1.34,11.24.83,16.39A1.46,1.46,0,0,0,2.14,18H15.72Z" fill="url(#be92901b-ec33-4c65-adf1-9b0eed06d677)"/><path d="M9,9.17a4.59,4.59,0,0,1-2.48-.73L9,14.86l2.44-6.38A4.53,4.53,0,0,1,9,9.17Z" fill="#fff" opacity="0.8"/><circle cx="9.01" cy="4.58" r="4.58" fill="url(#b46fc246-25d8-4398-8779-1042e8cacae7)"/></svg>';
        const userIconOverride = 'data:image/svg+xml;base64,PHN2ZyBpZD0iZTI0NjcxZjYtZjUwMS00OTUyLWEyZGItOGIwYjFkMzI5YzE3IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxOCAxOCI+PGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJiZTkyOTAxYi1lYzMzLTRjNjUtYWRmMS05YjBlZWQwNmQ2NzciIHgxPSI5IiB5MT0iNi44OCIgeDI9IjkiIHkyPSIyMC40NSIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPjxzdG9wIG9mZnNldD0iMC4yMiIgc3RvcC1jb2xvcj0iIzMyZDRmNSIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzE5OGFiMyIvPjwvbGluZWFyR3JhZGllbnQ+PGxpbmVhckdyYWRpZW50IGlkPSJiNDZmYzI0Ni0yNWQ4LTQzOTgtODc3OS0xMDQyZThjYWNhZTciIHgxPSI4LjYxIiB5MT0iLTAuNCIgeDI9IjkuNiIgeTI9IjExLjkyIiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHN0b3Agb2Zmc2V0PSIwLjIyIiBzdG9wLWNvbG9yPSIjMzJkNGY1Ii8+PHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjMTk4YWIzIi8+PC9saW5lYXJHcmFkaWVudD48L2RlZnM+PHRpdGxlPkljb24taWRlbnRpdHktMjMwPC90aXRsZT48cGF0aCBkPSJNMTUuNzIsMThhMS40NSwxLjQ1LDAsMCwwLDEuNDUtMS40NS40Ny40NywwLDAsMCwwLS4xN0MxNi41OSwxMS44MSwxNCw4LjA5LDksOC4wOVMxLjM0LDExLjI0LjgzLDE2LjM5QTEuNDYsMS40NiwwLDAsMCwyLjE0LDE4SDE1LjcyWiIgZmlsbD0idXJsKCNiZTkyOTAxYi1lYzMzLTRjNjUtYWRmMS05YjBlZWQwNmQ2NzcpIi8+PHBhdGggZD0iTTksOS4xN2E0LjU5LDQuNTksMCwwLDEtMi40OC0uNzNMOSwxNC44NmwyLjQ0LTYuMzhBNC41Myw0LjUzLDAsMCwxLDksOS4xN1oiIGZpbGw9IiNmZmYiIG9wYWNpdHk9IjAuOCIvPjxjaXJjbGUgY3g9IjkuMDEiIGN5PSI0LjU4IiByPSI0LjU4IiBmaWxsPSJ1cmwoI2I0NmZjMjQ2LTI1ZDgtNDM5OC04Nzc5LTEwNDJlOGNhY2FlNykiLz48L3N2Zz4=';
        const userIconDataUri = (userIconOverride && !userIconOverride.includes('…')) ? userIconOverride : svgIcon(defaultUserIconSvg);

        // Microsoft-inspired icon set for each node type
        const nodeIcons = {
            user: userIconDataUri,
            group: svgIcon('<svg id="a5c2c34a-a5f9-4043-a084-e51b74497895" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="f97360fa-fd13-420b-9b43-74b8dde83a11" x1="6.7" y1="7.26" x2="6.7" y2="18.36" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient><linearGradient id="b2ab4071-529d-4450-9443-e6dc0939cc4e" x1="6.42" y1="1.32" x2="7.23" y2="11.39" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient></defs><title>Icon-identity-223</title><path d="M17.22,13.92a.79.79,0,0,0,.8-.79A.28.28,0,0,0,18,13c-.31-2.5-1.74-4.54-4.46-4.54S9.35,10.22,9.07,13a.81.81,0,0,0,.72.88h7.43Z" fill="#0078d4"/><path d="M13.55,9.09a2.44,2.44,0,0,1-1.36-.4l1.35,3.52,1.33-3.49A2.54,2.54,0,0,1,13.55,9.09Z" fill="#fff" opacity="0.8"/><circle cx="13.55" cy="6.58" r="2.51" fill="#0078d4"/><path d="M12.19,16.36a1.19,1.19,0,0,0,1.19-1.19.66.66,0,0,0,0-.14c-.47-3.74-2.6-6.78-6.66-6.78S.44,10.83,0,15a1.2,1.2,0,0,0,1.07,1.31h11.1Z" fill="url(#f97360fa-fd13-420b-9b43-74b8dde83a11)"/><path d="M6.77,9.14a3.72,3.72,0,0,1-2-.6l2,5.25,2-5.21A3.81,3.81,0,0,1,6.77,9.14Z" fill="#fff" opacity="0.8"/><circle cx="6.74" cy="5.39" r="3.75" fill="url(#b2ab4071-529d-4450-9443-e6dc0939cc4e)"/></svg>'),
            role: svgIcon('<svg id="a12d75ea-cbb6-44fa-832a-e54cce009101" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="e2b13d81-97e0-465a-b9ed-b7f57e1b3f8c" x1="9" y1="16.79" x2="9" y2="1.21" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#0078d4"/><stop offset="0.06" stop-color="#0a7cd7"/><stop offset="0.34" stop-color="#2e8ce1"/><stop offset="0.59" stop-color="#4897e9"/><stop offset="0.82" stop-color="#589eed"/><stop offset="1" stop-color="#5ea0ef"/></linearGradient></defs><title>Icon-identity-233</title><path d="M16.08,8.44c0,4.57-5.62,8.25-6.85,9a.43.43,0,0,1-.46,0c-1.23-.74-6.85-4.42-6.85-9V2.94a.44.44,0,0,1,.43-.44C6.73,2.39,5.72.5,9,.5s2.27,1.89,6.65,2a.44.44,0,0,1,.43.44Z" fill="#0078d4"/><path d="M15.5,8.48c0,4.2-5.16,7.57-6.29,8.25a.4.4,0,0,1-.42,0C7.66,16.05,2.5,12.68,2.5,8.48v-5A.41.41,0,0,1,2.9,3C6.92,2.93,6,1.21,9,1.21S11.08,2.93,15.1,3a.41.41,0,0,1,.4.4Z" fill="url(#e2b13d81-97e0-465a-b9ed-b7f57e1b3f8c)"/><path d="M11.85,7.66h-.4V6.24a2.62,2.62,0,0,0-.7-1.81,2.37,2.37,0,0,0-3.48,0,2.61,2.61,0,0,0-.7,1.81V7.66h-.4A.32.32,0,0,0,5.82,8v3.68a.32.32,0,0,0,.33.32h5.7a.32.32,0,0,0,.33-.32V8A.32.32,0,0,0,11.85,7.66Zm-1.55,0H7.7V6.22a1.43,1.43,0,0,1,.41-1,1.19,1.19,0,0,1,1.78,0,1.56,1.56,0,0,1,.16.2h0a1.4,1.4,0,0,1,.25.79Z" fill="#ffbd02"/><path d="M6.15,7.66h5.7a.32.32,0,0,1,.21.08L5.94,11.9a.33.33,0,0,1-.12-.24V8A.32.32,0,0,1,6.15,7.66Z" fill="#ffe452"/><path d="M11.85,7.66H6.15a.32.32,0,0,0-.21.08l6.12,4.16a.3.3,0,0,0,.12-.24V8A.32.32,0,0,0,11.85,7.66Z" fill="#ffd400" opacity="0.5"/></svg>'),
            servicePrincipal: svgIcon('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="b05ecef1-bdba-47cb-a2a6-665a5bf9ae79" x1="9" y1="19.049" x2="9" y2="1.048" gradientUnits="userSpaceOnUse"><stop offset="0.2" stop-color="#0078d4"/><stop offset="0.287" stop-color="#1380da"/><stop offset="0.495" stop-color="#3c91e5"/><stop offset="0.659" stop-color="#559cec"/><stop offset="0.759" stop-color="#5ea0ef"/></linearGradient></defs><g id="adc593fc-9575-4f0f-b9cc-4803103092a4"><g><rect x="1" y="1" width="16" height="16" rx="0.534" fill="url(#b05ecef1-bdba-47cb-a2a6-665a5bf9ae79)"/><g><g opacity="0.95"><rect x="2.361" y="2.777" width="3.617" height="3.368" rx="0.14" fill="#fff"/><rect x="7.192" y="2.777" width="3.617" height="3.368" rx="0.14" fill="#fff"/><rect x="12.023" y="2.777" width="3.617" height="3.368" rx="0.14" fill="#fff"/></g><rect x="2.361" y="7.28" width="8.394" height="3.368" rx="0.14" fill="#fff" opacity="0.45"/><rect x="12.009" y="7.28" width="3.617" height="3.368" rx="0.14" fill="#fff" opacity="0.9"/><rect x="2.361" y="11.854" width="13.186" height="3.368" rx="0.14" fill="#fff" opacity="0.75"/></g></g></g></svg>'),
            application: svgIcon('<svg id="a76a0103-ce03-4d58-859d-4c27e02925d2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="efeb8e96-2af0-4681-9a6a-45f9b0262f19" x1="-6518.78" y1="1118.86" x2="-6518.78" y2="1090.06" gradientTransform="matrix(0.5, 0, 0, -0.5, 3267.42, 559.99)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#5ea0ef"/><stop offset="0.18" stop-color="#589eed"/><stop offset="0.41" stop-color="#4897e9"/><stop offset="0.66" stop-color="#2e8ce1"/><stop offset="0.94" stop-color="#0a7cd7"/><stop offset="1" stop-color="#0078d4"/></linearGradient></defs><path d="M5.67,10.61H10v4.32H5.67Zm-5-5.76H5V.53H1.23a.6.6,0,0,0-.6.6Zm.6,10.08H5V10.61H.63v3.72A.6.6,0,0,0,1.23,14.93Zm-.6-5H5V5.57H.63Zm10.08,5h3.72a.6.6,0,0,0,.6-.6V10.61H10.71Zm-5-5H10V5.57H5.67Zm5,0H15V5.57H10.71Zm0-9.36V4.85H15V1.13a.6.6,0,0,0-.6-.6Zm-5,4.32H10V.53H5.67Z" fill="url(#efeb8e96-2af0-4681-9a6a-45f9b0262f19)"/><polygon points="17.37 10.7 17.37 15.21 13.5 17.47 13.5 12.96 17.37 10.7" fill="#32bedd"/><polygon points="17.37 10.7 13.5 12.97 9.63 10.7 13.5 8.44 17.37 10.7" fill="#9cebff"/><polygon points="13.5 12.97 13.5 17.47 9.63 15.21 9.63 10.7 13.5 12.97" fill="#50e6ff"/><polygon points="9.63 15.21 13.5 12.96 13.5 17.47 9.63 15.21" fill="#9cebff"/><polygon points="17.37 15.21 13.5 12.96 13.5 17.47 17.37 15.21" fill="#50e6ff"/></svg>')
        
            };
        
        // Transform nodes for vis-network with iconography
        const nodes = new vis.DataSet(graphNodes.map(node => {
            const icon = nodeIcons[node.type];
            const hasIcon = Boolean(icon);
            const baseColor = node.type === 'user' ? '#4CAF50' :
                              node.type === 'group' ? '#2196F3' :
                              node.type === 'role' ? '#FF5722' :
                              node.type === 'servicePrincipal' ? '#9C27B0' :
                              node.type === 'application' ? '#FF9800' : '#999';
            const fallbackShape = node.type === 'role' ? 'diamond' : (node.type === 'group' ? 'box' : 'dot');
            const config = {
                id: node.id,
                label: node.label,
                group: node.type,
                title: node.label + ' (' + node.type + ')',
                shape: hasIcon ? 'image' : fallbackShape,
                borderWidth: hasIcon ? 0 : 2,
                font: { color: '#333', size: 14 }
            };
            if (hasIcon) {
                config.image = icon;
            } else {
                config.color = {
                    background: baseColor,
                    border: '#333'
                };
            }
            return config;
        }));
        
        // Update legend imagery to keep it in sync with node icons
        document.querySelectorAll('.legend-icon').forEach(el => {
            const type = el.getAttribute('data-icon-type');
            if (type && nodeIcons[type]) {
                el.src = nodeIcons[type];
            }
        });
        
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
        const originalNodeStyles = {};
        graphNodes.forEach(node => {
            const hasIcon = Boolean(nodeIcons[node.type]);
            const baseColor = node.type === 'user' ? '#4CAF50' : 
                              node.type === 'group' ? '#2196F3' :
                              node.type === 'role' ? '#FF5722' :
                              node.type === 'servicePrincipal' ? '#9C27B0' :
                              node.type === 'application' ? '#FF9800' : '#999';
            originalNodeStyles[node.id] = {
                hasIcon,
                color: hasIcon ? null : {
                    background: baseColor,
                    border: '#333'
                }
            };
        });
        
        // Track selected nodes for cumulative path highlighting
        const selectedNodes = new Set();
        
        // Function to get all connected nodes (directly or through path)
        function getConnectedNodes(nodeId, visited = new Set(), excludeOtherPrincipals = false, originNodeId = null, originNodeType = null, depth = 0) {
            if (visited.has(nodeId)) return visited;
            visited.add(nodeId);
            
            // If this is the first call, set originNodeId and originNodeType
            if (originNodeId === null) {
                originNodeId = nodeId;
                const originNode = nodes.get(nodeId);
                originNodeType = originNode ? originNode.type : null;
            }
            
            const currentNode = nodes.get(nodeId);
            const currentType = currentNode ? currentNode.type : null;
            
            // Get all directly connected nodes by querying edges dataset
            const allEdges = edges.get();
            const connectedNodes = [];
            allEdges.forEach(edge => {
                if (edge.from === nodeId && !visited.has(edge.to)) {
                    connectedNodes.push(edge.to);
                } else if (edge.to === nodeId && !visited.has(edge.from)) {
                    connectedNodes.push(edge.from);
                }
            });
            
            // Recursively traverse connected nodes
            connectedNodes.forEach(connId => {
                if (!visited.has(connId)) {
                    const connNode = nodes.get(connId);
                    if (!connNode) return;
                    
                    let shouldSkip = false;
                    let shouldRecurse = true;
                    
                    if (excludeOtherPrincipals) {
                        // Skip other users (not the origin)
                        if (connNode.type === 'user' && connId !== originNodeId) {
                            shouldSkip = true;
                        }
                        
                        // If origin is user or group, limit traversal depth
                        if ((originNodeType === 'user' || originNodeType === 'group') && !shouldSkip) {
                            // From user: can go to groups (depth 0+), then to roles/SPNs/apps
                            // From group: can go to roles/SPNs/apps (depth 0) and users (depth 0)
                            
                            if (originNodeType === 'user') {
                                if (depth === 0) {
                                    // Direct connections from user
                                    if (connNode.type === 'role' || connNode.type === 'servicePrincipal' || connNode.type === 'application') {
                                        // Direct role/SPN/app assignments - include but don't recurse
                                        shouldRecurse = false;
                                    } else if (connNode.type === 'group') {
                                        // Groups - recurse to find their role assignments and nested groups
                                        shouldRecurse = true;
                                    }
                                } else if (depth >= 1 && depth <= 2) {
                                    // Depth 1-2: from groups, can reach roles/SPNs/apps or nested groups
                                    if (connNode.type === 'role' || connNode.type === 'servicePrincipal' || connNode.type === 'application') {
                                        // Roles/SPNs/apps - include but don't recurse
                                        shouldRecurse = false;
                                    } else if (connNode.type === 'group' && connId !== originNodeId) {
                                        // Nested groups - recurse one more level
                                        shouldRecurse = true;
                                    } else {
                                        shouldSkip = true;
                                    }
                                } else {
                                    // Depth 3+: stop traversing
                                    shouldSkip = true;
                                }
                            } else if (originNodeType === 'group') {
                                if (depth === 0) {
                                    // Direct connections from group: users, roles, SPNs, apps, nested groups
                                    if (connNode.type === 'role' || connNode.type === 'servicePrincipal' || connNode.type === 'application') {
                                        // Roles/SPNs/apps - include but don't recurse
                                        shouldRecurse = false;
                                    } else if (connNode.type === 'group' && connId !== originNodeId) {
                                        // Nested groups - recurse to find their assignments
                                        shouldRecurse = true;
                                    } else if (connNode.type === 'user' && connId !== originNodeId) {
                                        // Members - include but don't recurse
                                        shouldRecurse = false;
                                    }
                                } else if (depth === 1) {
                                    // Depth 1 from group: can reach roles/SPNs/apps from nested groups
                                    if (connNode.type === 'role' || connNode.type === 'servicePrincipal' || connNode.type === 'application') {
                                        shouldRecurse = false;
                                    } else {
                                        shouldSkip = true;
                                    }
                                } else {
                                    // Depth 2+: stop traversing
                                    shouldSkip = true;
                                }
                            }
                        }
                    }
                    
                    // Add node to visited if not skipping
                    if (!shouldSkip) {
                        visited.add(connId);
                        
                        // Recurse if allowed
                        if (shouldRecurse) {
                            getConnectedNodes(connId, visited, excludeOtherPrincipals, originNodeId, originNodeType, depth + 1);
                        }
                    }
                }
            });
            
            return visited;
        }
        
        // Function to highlight escalation path
        function highlightPath(nodeId, additive = false) {
            // If not additive mode, clear previous selections
            if (!additive) {
                selectedNodes.clear();
            }
            
            // Add this node to selected set
            selectedNodes.add(nodeId);
            
            // Collect all path nodes from all selected nodes
            const allPathNodes = new Set();
            const allPathEdges = new Set();
            
            selectedNodes.forEach(selectedId => {
                // Determine if selected node is a user or group (principals that should exclude other principals)
                const selectedNode = nodes.get(selectedId);
                const isPrincipalSelected = selectedNode && (selectedNode.type === 'user' || selectedNode.type === 'group');
                
                // Get connected nodes, excluding other users/groups if a user or group is selected
                const pathNodes = getConnectedNodes(selectedId, new Set(), isPrincipalSelected);
                
                // Add all path nodes to the combined set
                pathNodes.forEach(nId => allPathNodes.add(nId));
                
                // Find all edges in the path
                pathNodes.forEach(nId => {
                    const connEdges = network.getConnectedEdges(nId);
                    connEdges.forEach(edgeId => {
                        const edge = edges.get(edgeId);
                        if (edge && pathNodes.has(edge.from) && pathNodes.has(edge.to)) {
                            allPathEdges.add(edgeId);
                        }
                    });
                });
            });
            
            // Hide nodes not in path, show nodes in path
            const updates = [];
            const allNodes = nodes.get();
            allNodes.forEach(node => {
                const baseStyle = originalNodeStyles[node.id] || {};
                if (allPathNodes.has(node.id)) {
                    // Highlighted nodes - shown
                    const isSelected = selectedNodes.has(node.id);
                    const update = {
                        id: node.id,
                        borderWidth: baseStyle.hasIcon ? (isSelected ? 4 : 0) : (isSelected ? 6 : 4),
                        font: { color: '#000', size: isSelected ? 18 : 16, bold: true },
                        hidden: false,
                        shadow: baseStyle.hasIcon && isSelected,
                        shadowColor: 'rgba(0,0,0,0.4)',
                        shadowSize: baseStyle.hasIcon && isSelected ? 12 : 0
                    };
                    if (baseStyle.color) {
                        update.color = {
                            background: baseStyle.color.background,
                            border: isSelected ? '#FFD700' : '#000',
                            highlight: {
                                background: baseStyle.color.background,
                                border: isSelected ? '#FFD700' : '#000'
                            }
                        };
                    }
                    updates.push(update);
                } else {
                    // Hide nodes not in path
                    updates.push({
                        id: node.id,
                        hidden: true,
                        shadow: false,
                        shadowSize: 0
                    });
                }
            });
            nodes.update(updates);
            
            // Show edges in path with color coding based on relationship type
            const edgeUpdates = [];
            const allEdges = edges.get();
            allEdges.forEach(edge => {
                if (allPathEdges.has(edge.id)) {
                    // Determine edge color based on type and label
                    let edgeColor = '#999';
                    let edgeWidth = 2;
                    let isDashed = false;
                    const edgeLabel = (edge.label || '').toLowerCase();
                    
                    // Color coding based on edge label/type
                    if (edgeLabel.includes('member')) {
                        edgeColor = '#2196F3';  // Blue for member relationships
                        edgeWidth = 2.5;
                    } else if (edgeLabel.includes('owner')) {
                        edgeColor = '#FF9800';  // Orange for ownership
                        edgeWidth = 2.5;
                    } else if (edgeLabel.includes('eligible')) {
                        edgeColor = '#9C27B0';  // Purple for PIM eligible
                        edgeWidth = 2;
                        isDashed = true;
                    } else if (edgeLabel.includes('pim active') || edgeLabel.includes('active')) {
                        edgeColor = '#4CAF50';  // Green for PIM active
                        edgeWidth = 2.5;
                    } else if (edgeLabel.includes('direct')) {
                        edgeColor = '#FF5722';  // Red for direct assignments
                        edgeWidth = 3;
                    } else if (edge.edgeType === 'has_role') {
                        edgeColor = '#FF5722';  // Red for role assignments
                        edgeWidth = 2.5;
                    }
                    
                    edgeUpdates.push({
                        id: edge.id,
                        width: edgeWidth,
                        color: { color: edgeColor, opacity: 1 },
                        hidden: false,
                        dashes: isDashed
                    });
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
            filterRiskTable(Array.from(allPathNodes));
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
            // Clear selected nodes set
            selectedNodes.clear();
            
            const updates = [];
            graphNodes.forEach(node => {
                const baseStyle = originalNodeStyles[node.id] || {};
                const update = {
                    id: node.id,
                    borderWidth: baseStyle.hasIcon ? 0 : 2,
                    font: { color: '#333', size: 14 },
                    hidden: false,
                    shadow: false,
                    shadowSize: 0
                };
                if (baseStyle.color) {
                    update.color = baseStyle.color;
                }
                updates.push(update);
            });
            nodes.update(updates);
            
            const edgeUpdates = [];
            const allEdges = edges.get();
            allEdges.forEach(edge => {
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
                
                // Check if Ctrl/Cmd key is pressed for additive selection
                const isAdditive = params.event.srcEvent.ctrlKey || params.event.srcEvent.metaKey;
                
                highlightPath(nodeId, isAdditive);
                
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
            }
            // Don't reset on canvas click - keep selections persistent
        });
        
        // Filter functionality
        function applyFilters() {
            const searchTerm = document.getElementById('nodeFilter').value.toLowerCase();
            const typeFilter = document.getElementById('typeFilter').value;
            const assignmentFilter = document.getElementById('assignmentFilter').value;
            
            // If assignment filter is set, filter edges first
            if (assignmentFilter) {
                const allEdges = edges.get();
                const edgeUpdates = [];
                const validNodeIds = new Set();
                
                allEdges.forEach(edge => {
                    let matches = false;
                    const edgeLabel = (edge.label || '').toLowerCase();
                    
                    if (assignmentFilter === 'member' && edgeLabel === 'member') {
                        matches = true;
                    } else if (assignmentFilter === 'active' && (edgeLabel === 'direct' || edgeLabel === 'pim active')) {
                        matches = true;
                    } else if (assignmentFilter === 'eligible' && edgeLabel === 'eligible') {
                        matches = true;
                    }
                    
                    if (matches) {
                        validNodeIds.add(edge.from);
                        validNodeIds.add(edge.to);
                        edgeUpdates.push({
                            id: edge.id,
                            hidden: false
                        });
                    } else {
                        edgeUpdates.push({
                            id: edge.id,
                            hidden: true
                        });
                    }
                });
                edges.update(edgeUpdates);
                
                // Filter nodes based on edges and other filters
                const matchingNodes = graphNodes.filter(node => {
                    const matchesSearch = !searchTerm || node.label.toLowerCase().includes(searchTerm);
                    const matchesType = !typeFilter || node.type === typeFilter;
                    const matchesAssignment = !assignmentFilter || validNodeIds.has(node.id);
                    return matchesSearch && matchesType && matchesAssignment;
                });
                
                const nodeUpdates = [];
                const allNodes = nodes.get();
                const matchingIds = new Set(matchingNodes.map(n => n.id));
                
                allNodes.forEach(node => {
                    if (matchingIds.has(node.id)) {
                        const baseStyle = originalNodeStyles[node.id] || {};
                        const update = {
                            id: node.id,
                            borderWidth: baseStyle.hasIcon ? 0 : 4,
                            font: { color: '#000', size: 16 },
                            hidden: false,
                            shadow: false,
                            shadowSize: 0
                        };
                        if (baseStyle.color) {
                            update.color = baseStyle.color;
                        }
                        nodeUpdates.push(update);
                    } else {
                        nodeUpdates.push({
                            id: node.id,
                            hidden: true
                        });
                    }
                });
                nodes.update(nodeUpdates);
                
            } else {
                // No assignment filter - use standard filtering
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
                    const allNodes = nodes.get();
                    allNodes.forEach(node => {
                        if (matchingIds.has(node.id)) {
                            const baseStyle = originalNodeStyles[node.id] || {};
                            const update = {
                                id: node.id,
                                borderWidth: baseStyle.hasIcon ? 0 : 4,
                                font: { color: '#000', size: 16 },
                                hidden: false,
                                shadow: false,
                                shadowSize: 0
                            };
                            if (baseStyle.color) {
                                update.color = baseStyle.color;
                            }
                            updates.push(update);
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
                    const allNodes = nodes.get();
                    allNodes.forEach(node => {
                        updates.push({
                            id: node.id,
                            hidden: true
                        });
                    });
                    nodes.update(updates);
                } else {
                    resetHighlight();
                }
            }
        }
        
        document.getElementById('nodeFilter').addEventListener('input', applyFilters);
        
        document.getElementById('typeFilter').addEventListener('change', applyFilters);
        
        document.getElementById('assignmentFilter').addEventListener('change', applyFilters);
        
        // Reset button
        document.getElementById('resetGraph').addEventListener('click', function() {
            document.getElementById('nodeFilter').value = '';
            document.getElementById('typeFilter').value = '';
            document.getElementById('assignmentFilter').value = '';
            resetHighlight();
            network.fit({
                animation: {
                    duration: 500,
                    easingFunction: 'easeInOutQuad'
                }
            });
        });
        
        // Navigation control buttons
        let initialViewPosition = null;
        
        // Store initial view position after stabilization
        network.once('stabilizationIterationsDone', function() {
            initialViewPosition = network.getViewPosition();
        });
        
        // Zoom in button
        document.getElementById('zoomIn').addEventListener('click', function() {
            const currentScale = network.getScale();
            network.moveTo({
                scale: currentScale * 1.2,
                animation: {
                    duration: 300,
                    easingFunction: 'easeInOutQuad'
                }
            });
        });
        
        // Zoom out button
        document.getElementById('zoomOut').addEventListener('click', function() {
            const currentScale = network.getScale();
            network.moveTo({
                scale: currentScale / 1.2,
                animation: {
                    duration: 300,
                    easingFunction: 'easeInOutQuad'
                }
            });
        });
        
        // Fit to screen button
        document.getElementById('fitGraph').addEventListener('click', function() {
            network.fit({
                animation: {
                    duration: 500,
                    easingFunction: 'easeInOutQuad'
                }
            });
        });
        
        // Reset view button
        document.getElementById('resetView').addEventListener('click', function() {
            if (initialViewPosition) {
                network.moveTo({
                    position: initialViewPosition,
                    scale: 1.0,
                    animation: {
                        duration: 500,
                        easingFunction: 'easeInOutQuad'
                    }
                });
            } else {
                network.fit({
                    animation: {
                        duration: 500,
                        easingFunction: 'easeInOutQuad'
                    }
                });
            }
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
    'New-ScEntraGraphData'
    'Export-ScEntraReport'
)
