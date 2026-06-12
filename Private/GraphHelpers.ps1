# Module-level shared state and helper utilities for Microsoft Graph interactions

# Module-level variable to store access token
$script:GraphAccessToken = $null
$script:GraphApiVersion = 'beta'
$script:GraphBaseUrl = "https://graph.microsoft.com/$script:GraphApiVersion"
$script:MissingPermissions = @()
$script:GraphPermissionHierarchy = @{
    'Directory.Read.All'            = @('User.Read.All', 'Group.Read.All', 'Application.Read.All', 'ServicePrincipalEndpoint.Read.All', 'DelegatedPermissionGrant.Read.All', 'RoleManagement.Read.Directory', 'RoleManagement.Read.All')
    'Directory.ReadWrite.All'       = @('User.ReadWrite.All', 'Group.ReadWrite.All', 'Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'Directory.Read.All', 'User.Read.All', 'Group.Read.All', 'Application.Read.All', 'DelegatedPermissionGrant.Read.All', 'RoleManagement.Read.Directory', 'RoleManagement.Read.All')
    'User.ReadWrite.All'            = @('User.Read.All')
    'Group.ReadWrite.All'           = @('Group.Read.All')
    'Application.ReadWrite.All'     = @('Application.Read.All')
    'RoleManagement.ReadWrite.Directory' = @('RoleManagement.Read.Directory', 'RoleManagement.Read.All')
}

function Get-GraphTokenScopeInfo {
    <#
    .SYNOPSIS
        Returns decoded token metadata including scopes and token type
    #>
    [CmdletBinding()]
    param()

    if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
        return $null
    }

    try {
        $tokenParts = $script:GraphAccessToken.Split('.')
        if ($tokenParts.Count -lt 2) {
            return $null
        }

        $tokenPayload = $tokenParts[1]
        while ($tokenPayload.Length % 4 -ne 0) {
            $tokenPayload += '='
        }

        $payloadBytes = [System.Convert]::FromBase64String($tokenPayload)
        $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
        $payload = $payloadJson | ConvertFrom-Json

        $isServicePrincipal = $false
        $tokenScopes = @()

        if ($payload.roles) {
            $tokenScopes = @($payload.roles)
            $isServicePrincipal = $true
            Write-Verbose "Token type: Service Principal (Application permissions)"
        }
        elseif ($payload.scp) {
            $tokenScopes = $payload.scp -split ' '
            Write-Verbose "Token type: Delegated (User permissions)"
        }

        if ($tokenScopes.Count -gt 0) {
            Write-Verbose "Token permissions: $($tokenScopes -join ', ')"
        }

        return [pscustomobject]@{
            IsServicePrincipal = $isServicePrincipal
            Scopes             = $tokenScopes
            Payload            = $payload
        }
    }
    catch {
        Write-Verbose "Could not decode token to inspect permissions: $_"
        return $null
    }
}

function Get-GraphPermissionCoverage {
    <#
    .SYNOPSIS
        Evaluates whether the current token satisfies the requested permissions
    .PARAMETER RequiredPermissions
        Array of permissions to validate
    .PARAMETER TokenInfo
        Optional pre-decoded token metadata
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredPermissions,

        [Parameter(Mandatory = $false)]
        [pscustomobject]$TokenInfo
    )

    if (-not $TokenInfo) {
        $TokenInfo = Get-GraphTokenScopeInfo
        if (-not $TokenInfo) {
            return $null
        }
    }

    $tokenScopes = $TokenInfo.Scopes
    $missing = @()
    $satisfied = @()
    $matchMap = @{}

    foreach ($required in $RequiredPermissions) {
        $hasPermission = $false
        $matchSource = $null

        foreach ($tokenScope in $tokenScopes) {
            if ($tokenScope -eq $required -or $tokenScope -like "*.$required" -or $tokenScope -like "$required.*") {
                $hasPermission = $true
                $matchSource = $tokenScope
                Write-Verbose "Found exact match for '$required': $tokenScope"
                break
            }
        }

        if (-not $hasPermission) {
            foreach ($higherPermission in $script:GraphPermissionHierarchy.Keys) {
                if ($tokenScopes -contains $higherPermission -and $script:GraphPermissionHierarchy[$higherPermission] -contains $required) {
                    $hasPermission = $true
                    $matchSource = $higherPermission
                    Write-Verbose "Permission '$required' satisfied by higher-level permission '$higherPermission'"
                    break
                }
            }
        }

        if ($hasPermission) {
            $satisfied += $required
            if ($matchSource) {
                $matchMap[$required] = $matchSource
            }
        }
        else {
            $missing += $required
        }
    }

    return [pscustomobject]@{
        TokenInfo            = $TokenInfo
        MissingPermissions   = $missing
        SatisfiedPermissions = $satisfied
        HasAll               = ($missing.Count -eq 0)
        HasAny               = ($satisfied.Count -gt 0)
        MatchMap             = $matchMap
    }
}

function Test-GraphPermissions {
    <#
    .SYNOPSIS
        Tests if the current token has the required permissions
    .PARAMETER RequiredPermissions
        Array of required permission scopes
    .PARAMETER ResourceName
        Name of the resource being accessed (for better error messages)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredPermissions,
        [Parameter(Mandatory = $false)]
        [string]$ResourceName = "resource"
    )

    if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
        Write-Warning "Not connected to Microsoft Graph. Please run Connect-ScEntraGraph first."
        return $false
    }

    $tokenInfo = Get-GraphTokenScopeInfo
    if (-not $tokenInfo) {
        Write-Verbose "Could not decode token to check permissions. Allowing API call to proceed."
        return $true
    }

    $coverage = Get-GraphPermissionCoverage -RequiredPermissions $RequiredPermissions -TokenInfo $tokenInfo
    if (-not $coverage) {
        return $true
    }

    if ($coverage.HasAll) {
        return $true
    }

    $missing = $coverage.MissingPermissions
    if ($missing.Count -gt 0) {
        $missingList = $missing -join ', '
        $tokenType = if ($tokenInfo.IsServicePrincipal) { "service principal" } else { "user token" }
        # Write-Warning "⚠️  Missing required permissions for $ResourceName ($tokenType): $missingList"

        if ($tokenInfo.IsServicePrincipal) {
            Write-Host "   Service Principal needs these application permissions granted with admin consent" -ForegroundColor Yellow
        }
        else {
            # Write-Host "   To resolve: Reconnect with required permissions or use an account with higher privileges" -ForegroundColor Yellow
        }

        foreach ($perm in $missing) {
            if ($script:MissingPermissions -notcontains $perm) {
                $script:MissingPermissions += $perm
            }
        }

        return $false
    }

    return $true
}

function Get-MissingPermissionsSummary {
    <#
    .SYNOPSIS
        Returns a summary of all missing permissions encountered during the session
    #>
    return $script:MissingPermissions | Select-Object -Unique
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

    $tokenInfo = Get-GraphTokenScopeInfo
    $probeUri = "$script:GraphBaseUrl/users?`$top=1&`$select=id"

    if ($tokenInfo -and $tokenInfo.Scopes) {
        if ($tokenInfo.Scopes -contains 'Application.Read.All') {
            $probeUri = "$script:GraphBaseUrl/applications?`$top=1&`$select=id"
        }
        elseif ($tokenInfo.Scopes -contains 'Group.Read.All') {
            $probeUri = "$script:GraphBaseUrl/groups?`$top=1&`$select=id"
        }
        elseif ($tokenInfo.Scopes -contains 'User.Read.All') {
            $probeUri = "$script:GraphBaseUrl/users?`$top=1&`$select=id"
        }
    }

    try {
        $null = Invoke-ScEntraGraphRequest -Uri $probeUri -Method GET -ErrorAction Stop
        return $true
    }
    catch {
        Write-Warning "Graph connection test failed. Token may be expired. Please re-authenticate."
        return $false
    }
}

function Invoke-ScEntraGraphRequest {
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
        Invoke-ScEntraGraphRequest -Uri "https://graph.microsoft.com/v1.0/users" -Method GET
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $false)]
        [string]$Method = 'GET',
        [Parameter(Mandatory = $false)]
        [object]$Body,
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec
    )

    if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
        throw "Not authenticated. Please run Connect-ScEntraGraph first."
    }

    # Get module version for User-Agent
    $moduleVersion = '1.0.2'
    try {
        $module = Get-Module -Name ScEntra -ErrorAction SilentlyContinue
        if ($module) {
            $moduleVersion = $module.Version.ToString()
        }
    } catch {
        # Fallback to default version
    }

    $headers = @{
        'Authorization'    = "Bearer $script:GraphAccessToken"
        'Content-Type'     = 'application/json'
        'ConsistencyLevel' = 'eventual'
        'User-Agent'       = "ScEntra/$moduleVersion (PowerShell/$($PSVersionTable.PSVersion))"
    }

    $params = @{
        Uri     = $Uri
        Method  = $Method
        Headers = $headers
    }

    if ($Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 10)
    }

    if ($PSBoundParameters.ContainsKey('TimeoutSec') -and $TimeoutSec -gt 0) {
        $params['TimeoutSec'] = $TimeoutSec
    }

    try {
        return Invoke-RestMethod @params -ErrorAction Stop
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

function Invoke-GraphRequest {
    <#
    .SYNOPSIS
        Backward-compatible wrapper around Invoke-ScEntraGraphRequest
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $false)]
        [string]$Method = 'GET',
        [Parameter(Mandatory = $false)]
        [object]$Body,
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec
    )

    Invoke-ScEntraGraphRequest @PSBoundParameters
}

function Get-ScEntraGraphEndpointTopLimit {
    <#
    .SYNOPSIS
        Returns recommended max `$top` for known Microsoft Graph collection endpoints
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $path = $null
    if ($Uri -match '^https://graph\.microsoft\.com/[^/]+(/[^?]+)') {
        $path = $Matches[1]
    }

    if (-not $path) {
        return $null
    }

    switch -Wildcard ($path) {
        '/users' { return 999 }
        '/groups' { return 999 }
        '/servicePrincipals' { return 999 }
        '/applications' { return 999 }
        '/directoryRoles' { return 999 }
        '/roleManagement/directory/roleEligibilityScheduleInstances' { return 999 }
        '/roleManagement/directory/roleAssignmentScheduleInstances' { return 999 }
        '/identityGovernance/privilegedAccess/group/*ScheduleInstances' { return 999 }
        default { return $null }
    }
}

function Remove-ScEntraGraphTopParameter {
    <#
    .SYNOPSIS
        Removes `$top from a Graph URL when an endpoint rejects custom page sizes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $updatedUri = $Uri -replace '([?&])\$top=\d+(&)?', '$1'
    $updatedUri = $updatedUri -replace '[?&]$', ''
    $updatedUri = $updatedUri -replace '\?&', '?'
    return $updatedUri
}

function Set-ScEntraGraphTopParameter {
    <#
    .SYNOPSIS
        Ensures a Graph collection URL uses the desired `$top` value
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $false)]
        [Nullable[int]]$Top
    )

    if ($null -eq $Top -or $Top.Value -le 0) {
        return $Uri
    }

    $resolvedTop = $Top.Value

    if ($Uri -match '(^|[?&])\$top=(\d+)') {
        $currentTop = [int]$Matches[2]
        if ($currentTop -ge $resolvedTop) {
            return $Uri
        }
        return ($Uri -replace '([?&])\$top=\d+', "`$1`$top=$resolvedTop")
    }

    if ($Uri.Contains('?')) {
        return "$Uri&`$top=$resolvedTop"
    }

    return "$Uri?`$top=$resolvedTop"
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
    $originalUri = $Uri
    $recommendedTop = Get-ScEntraGraphEndpointTopLimit -Uri $Uri
    $nextLink = Set-ScEntraGraphTopParameter -Uri $Uri -Top $recommendedTop
    $usingOptimizedTop = ($nextLink -ne $originalUri)
    $retriedWithoutTop = $false
    $pageCount = 0

    do {
        try {
            $pageCount++

            if ($ProgressActivity) {
                Write-Progress -Activity $ProgressActivity -Status "Fetching page $pageCount (retrieved $($allItems.Count) items so far)" -Id 1
            }

            $result = Invoke-ScEntraGraphRequest -Uri $nextLink -Method $Method

            if ($result.value) {
                $allItems += $result.value
            }
            elseif ($result) {
                $allItems += $result
            }

            $nextLink = $result.'@odata.nextLink'
        }
        catch {
            $errorMessage = $_.Exception.Message
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $errorMessage = "$errorMessage $($_.ErrorDetails.Message)"
            }

            if ($errorMessage -match 'does not support custom page sizes' -and $nextLink -match '(^|[?&])\$top=\d+') {
                $retryUriWithoutTop = Remove-ScEntraGraphTopParameter -Uri $nextLink
                if ($retryUriWithoutTop -ne $nextLink) {
                    Write-Verbose "Retrying Graph request without `$top due to endpoint limitation: $retryUriWithoutTop"
                    $nextLink = $retryUriWithoutTop
                    continue
                }
            }

            if ($pageCount -eq 1 -and $usingOptimizedTop -and -not $retriedWithoutTop) {
                Write-Verbose "Retrying initial Graph request without optimized `$top for endpoint compatibility: $originalUri"
                $nextLink = $originalUri
                $retriedWithoutTop = $true
                $pageCount = 0
                continue
            }

            Write-Error "Error fetching items from $nextLink : $_"
            break
        }
    } while ($nextLink)

    if ($ProgressActivity) {
        Write-Progress -Activity $ProgressActivity -Completed -Id 1
    }

    return $allItems
}

function Get-ScEntraEnvironmentSize {
    <#
    .SYNOPSIS
        Automatically determines environment size by querying Microsoft Graph API counts
    .DESCRIPTION
        Queries the actual counts of users, groups, service principals, and applications
        from Microsoft Graph API to determine the appropriate environment configuration.
    .EXAMPLE
        $config = Get-ScEntraEnvironmentSize
    #>
    [CmdletBinding()]
    param()

    if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
        throw "Not authenticated. Please run Connect-ScEntraGraph first."
    }

    Write-Host "Determining environment size by querying Microsoft Graph API..." -ForegroundColor Cyan

    $counts = @{
        Users = 0
        Groups = 0
        ServicePrincipals = 0
        Applications = 0
    }

    # Query each resource type count
    $endpoints = @{
        Users = "$script:GraphBaseUrl/users?`$top=1&`$count=true&`$select=id"
        Groups = "$script:GraphBaseUrl/groups?`$top=1&`$count=true&`$select=id"
        ServicePrincipals = "$script:GraphBaseUrl/servicePrincipals?`$top=1&`$count=true&`$select=id"
        Applications = "$script:GraphBaseUrl/applications?`$top=1&`$count=true&`$select=id"
    }

    foreach ($resourceType in $endpoints.Keys) {
        try {
            Write-Verbose "Querying $resourceType count..."
            $countResult = Invoke-ScEntraGraphRequest -Uri $endpoints[$resourceType] -Method GET
            if ($countResult.PSObject.Properties.Name -contains '@odata.count') {
                $counts[$resourceType] = [int]$countResult.'@odata.count'
            }
            else {
                throw "Count value was not returned by Microsoft Graph for $resourceType"
            }
        }
        catch {
            Write-Warning "Could not query $resourceType count: $_"
            Write-Warning "Falling back to conservative Enterprise configuration"
            # Return conservative defaults if we can't determine size
            return Get-ScEntraEnvironmentConfig -UserCount 100000 -GroupCount 50000 -ServicePrincipalCount 50000 -AppRegistrationCount 100000
        }
    }

    return Get-ScEntraEnvironmentConfig -UserCount $counts.Users -GroupCount $counts.Groups -ServicePrincipalCount $counts.ServicePrincipals -AppRegistrationCount $counts.Applications
}

function Get-ScEntraEnvironmentConfig {
    <#
    .SYNOPSIS
        Determines environment size and returns adaptive configuration for API throttling
    .PARAMETER UserCount
        Number of users in the tenant
    .PARAMETER GroupCount
        Number of groups in the tenant
    .PARAMETER ServicePrincipalCount
        Number of service principals in the tenant
    .PARAMETER AppRegistrationCount
        Number of app registrations in the tenant
    .EXAMPLE
        $config = Get-ScEntraEnvironmentConfig -UserCount 60000 -GroupCount 80000 -ServicePrincipalCount 120000 -AppRegistrationCount 260000
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$UserCount,
        [Parameter(Mandatory = $true)]
        [int]$GroupCount,
        [Parameter(Mandatory = $true)]
        [int]$ServicePrincipalCount,
        [Parameter(Mandatory = $true)]
        [int]$AppRegistrationCount
    )

    # Calculate environment score based on object counts
    $envScore = ($UserCount * 1) + ($GroupCount * 2) + ($ServicePrincipalCount * 0.5) + ($AppRegistrationCount * 0.5)

    # Determine environment profile
    $envProfile = if ($envScore -lt 25000) {
        "Small"
    }
    elseif ($envScore -lt 75000) {
        "Medium"
    }
    elseif ($envScore -lt 200000) {
        "Large"
    }
    else {
        "Enterprise"
    }

    # Adaptive configuration based on environment size
    $config = switch ($envProfile) {
        "Small" {
            @{
                Profile = "Small (<25k objects)"
                BatchThrottleLimit = 5
                DelayBetweenBatches = 0
                MaxBatchSize = 20
                UseParallelEscalation = $true
                EscalationThrottleLimit = 5
                CircuitBreakerThreshold = 20
            }
        }
        "Medium" {
            @{
                Profile = "Medium (25k-75k objects)"
                BatchThrottleLimit = 3
                DelayBetweenBatches = 100
                MaxBatchSize = 20
                UseParallelEscalation = $true
                EscalationThrottleLimit = 3
                CircuitBreakerThreshold = 15
            }
        }
        "Large" {
            @{
                Profile = "Large (75k-200k objects)"
                BatchThrottleLimit = 2
                DelayBetweenBatches = 250
                MaxBatchSize = 15
                UseParallelEscalation = $false
                EscalationThrottleLimit = 1
                CircuitBreakerThreshold = 10
            }
        }
        "Enterprise" {
            @{
                Profile = "Enterprise (200k+ objects)"
                BatchThrottleLimit = 1
                DelayBetweenBatches = 500
                MaxBatchSize = 10
                UseParallelEscalation = $false
                EscalationThrottleLimit = 1
                CircuitBreakerThreshold = 5
            }
        }
    }

    return [PSCustomObject]$config
}

function Invoke-GraphBatchRequest {
    <#
    .SYNOPSIS
        Makes a batch request to Microsoft Graph API for multiple operations
    .PARAMETER Requests
        Array of request objects with id, method, and url properties
    .PARAMETER MaxBatchSize
        Maximum number of requests per batch (default: 20, Graph API limit)
    .PARAMETER ThrottleLimit
        Maximum number of concurrent batch operations (default: 5)
    .PARAMETER DelayBetweenBatches
        Delay in milliseconds between processing batches (default: 0)
    .EXAMPLE
        $requests = @(
            @{ id = "1"; method = "GET"; url = "/groups/id1/members" }
            @{ id = "2"; method = "GET"; url = "/groups/id2/members" }
        )
        Invoke-GraphBatchRequest -Requests $requests -ThrottleLimit 2 -DelayBetweenBatches 250
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Requests,
        [Parameter(Mandatory = $false)]
        [int]$MaxBatchSize = 20,
        [Parameter(Mandatory = $false)]
        [int]$ThrottleLimit = 5,
        [Parameter(Mandatory = $false)]
        [int]$DelayBetweenBatches = 0
    )

    if ([string]::IsNullOrEmpty($script:GraphAccessToken)) {
        throw "Not authenticated. Please run Connect-ScEntraGraph first."
    }

    $allResponses = @{}
    $batches = @()

    for ($i = 0; $i -lt $Requests.Count; $i += $MaxBatchSize) {
        $batchSize = [Math]::Min($MaxBatchSize, $Requests.Count - $i)
        $batches += , @($Requests[$i..($i + $batchSize - 1)])
    }

    Write-Verbose "Processing $($Requests.Count) requests in $($batches.Count) batches (ThrottleLimit: $ThrottleLimit, Delay: ${DelayBetweenBatches}ms)"

    $graphBaseUrl = $script:GraphBaseUrl
    $graphAccessToken = $script:GraphAccessToken

    # Choose processing strategy based on throttle limit and delay requirements
    if ($ThrottleLimit -eq 1 -or $DelayBetweenBatches -gt 0) {
        # Sequential processing for large environments or when delays are needed
        Write-Verbose "Using sequential batch processing for large environment compatibility"
        
        foreach ($batch in $batches) {
            $batchBody = @{ requests = $batch }

            try {
                $headers = @{
                    'Authorization'    = "Bearer $graphAccessToken"
                    'Content-Type'     = 'application/json'
                    'ConsistencyLevel' = 'eventual'
                }

                $batchUri = "$graphBaseUrl/`$batch"
                # Add User-Agent to batch request headers
                $batchHeaders = $headers.Clone()
                if (-not $batchHeaders.ContainsKey('User-Agent')) {
                    $moduleVersion = '1.0.0'
                    try {
                        $module = Get-Module -Name ScEntra -ErrorAction SilentlyContinue
                        if ($module) {
                            $moduleVersion = $module.Version.ToString()
                        }
                    } catch { }
                    $batchHeaders['User-Agent'] = "ScEntra/$moduleVersion (PowerShell/$($PSVersionTable.PSVersion))"
                }
                
                $response = Invoke-RestMethod -Uri $batchUri -Method POST -Headers $batchHeaders -Body ($batchBody | ConvertTo-Json -Depth 10) -ErrorAction Stop

                # Process responses
                foreach ($resp in $response.responses) {
                    $allResponses[$resp.id] = $resp
                }

                # Add delay between batches if specified
                if ($DelayBetweenBatches -gt 0) {
                    Start-Sleep -Milliseconds $DelayBetweenBatches
                }
            }
            catch {
                Write-Error "Batch request failed: $($_.Exception.Message)"
                throw
            }
        }
    }
    else {
        # Parallel processing for smaller environments
        Write-Verbose "Using parallel batch processing for optimal performance"
        
        $batches | ForEach-Object -Parallel {
            $batch = $_
            $batchBody = @{ requests = $batch }

            try {
                $headers = @{
                    'Authorization'    = "Bearer $using:graphAccessToken"
                    'Content-Type'     = 'application/json'
                    'ConsistencyLevel' = 'eventual'
                }

                $batchUri = "$using:graphBaseUrl/`$batch"
                # Add User-Agent to batch request headers
                $batchHeaders = $headers.Clone()
                if (-not $batchHeaders.ContainsKey('User-Agent')) {
                    $moduleVersion = '1.0.0'
                    try {
                        $module = Get-Module -Name ScEntra -ErrorAction SilentlyContinue
                        if ($module) {
                            $moduleVersion = $module.Version.ToString()
                        }
                    } catch { }
                    $batchHeaders['User-Agent'] = "ScEntra/$moduleVersion (PowerShell/$($PSVersionTable.PSVersion))"
                }
                
                $response = Invoke-RestMethod -Uri $batchUri -Method POST -Headers $batchHeaders -Body ($batchBody | ConvertTo-Json -Depth 10) -ErrorAction Stop

                # Return the responses
                $response.responses
            }
            catch {
                # In parallel, we can't throw, so return error info
                [PSCustomObject]@{ Error = $_.Exception.Message; Batch = $batch }
            }
        } -ThrottleLimit $ThrottleLimit | ForEach-Object {
            if ($_.Error) {
                Write-Error "Batch request failed: $($_.Error)"
                throw $_.Error
            }
            foreach ($resp in $_) {
                $allResponses[$resp.id] = $resp
            }
        }
    }

    return $allResponses
}

function Get-PagedBatchItems {
    <#
    .SYNOPSIS
        Helper function to collect all items from a batch response with pagination
    .PARAMETER Response
        The batch response object
    .EXAMPLE
        $items = Get-PagedBatchItems -Response $batchResponse
    #>
    param(
        [Parameter(Mandatory = $true)]
        $Response
    )

    $items = @()
    if (-not $Response) { return $items }
    if ($Response.body -and $Response.body.value) {
        $items += $Response.body.value
    }

    $nextLink = if ($Response.body) { $Response.body.'@odata.nextLink' } else { $null }
    while ($nextLink) {
        try {
            $nextResult = Invoke-ScEntraGraphRequest -Uri $nextLink -Method GET -ErrorAction Stop
            if ($nextResult.value) {
                $items += $nextResult.value
            }
            $nextLink = $nextResult.'@odata.nextLink'
        }
        catch {
            Write-Verbose "Failed to fetch additional page for batch response $($Response.id): $_"
            break
        }
    }

    return $items
}

function Get-ScEntraOrganizationInfo {
    <#
    .SYNOPSIS
        Gets organization information from Microsoft Graph
    .DESCRIPTION
        Retrieves tenant organization details including display name, ID, and verified domains
    .EXAMPLE
        Get-ScEntraOrganizationInfo
    #>
    [CmdletBinding()]
    param()

    try {
        $orgUri = "$script:GraphBaseUrl/organization"
        $response = Invoke-ScEntraGraphRequest -Uri $orgUri -Method GET
        
        if ($response.value -and $response.value.Count -gt 0) {
            $org = $response.value[0]
            return @{
                Id = $org.id
                DisplayName = $org.displayName
                TenantId = $org.id
                VerifiedDomains = $org.verifiedDomains | Where-Object { $_.isDefault } | Select-Object -ExpandProperty name -First 1
                TechnicalContact = $org.technicalNotificationMails -join ', '
            }
        }
        return $null
    }
    catch {
        Write-Verbose "Could not retrieve organization information with current token: $($_.Exception.Message)"
        return $null
    }
}
