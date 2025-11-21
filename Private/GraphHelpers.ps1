# Module-level shared state and helper utilities for Microsoft Graph interactions

# Module-level variable to store access token
$script:GraphAccessToken = $null
$script:GraphApiVersion = 'beta'
$script:GraphBaseUrl = "https://graph.microsoft.com/$script:GraphApiVersion"
$script:MissingPermissions = @()

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

    # Decode JWT token to check permissions
    try {
        $tokenParts = $script:GraphAccessToken.Split('.')
        $tokenPayload = $tokenParts[1]
        
        # Add padding if needed
        while ($tokenPayload.Length % 4 -ne 0) {
            $tokenPayload += '='
        }
        
        $payloadBytes = [System.Convert]::FromBase64String($tokenPayload)
        $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
        $payload = $payloadJson | ConvertFrom-Json
        
        # Get the scopes from the token
        $tokenScopes = @()
        if ($payload.scp) {
            $tokenScopes = $payload.scp -split ' '
        }
        elseif ($payload.roles) {
            $tokenScopes = $payload.roles
        }
        
        # Define permission hierarchy - higher-level permissions that satisfy lower-level ones
        $permissionHierarchy = @{
            'Directory.Read.All' = @('User.Read.All', 'Group.Read.All', 'Application.Read.All', 'ServicePrincipalEndpoint.Read.All')
            'Directory.ReadWrite.All' = @('User.ReadWrite.All', 'Group.ReadWrite.All', 'Application.ReadWrite.All', 'Directory.Read.All', 'User.Read.All', 'Group.Read.All', 'Application.Read.All')
            'User.ReadWrite.All' = @('User.Read.All')
            'Group.ReadWrite.All' = @('Group.Read.All')
            'Application.ReadWrite.All' = @('Application.Read.All')
        }
        
        # Check if all required permissions are present
        $missing = @()
        foreach ($required in $RequiredPermissions) {
            $hasPermission = $false
            
            # Check for exact match or pattern match
            foreach ($tokenScope in $tokenScopes) {
                if ($tokenScope -eq $required -or $tokenScope -like "*.$required" -or $tokenScope -like "$required.*") {
                    $hasPermission = $true
                    break
                }
            }
            
            # If not found, check if a higher-level permission satisfies this requirement
            if (-not $hasPermission) {
                foreach ($higherPermission in $permissionHierarchy.Keys) {
                    if ($tokenScopes -contains $higherPermission -and $permissionHierarchy[$higherPermission] -contains $required) {
                        $hasPermission = $true
                        Write-Verbose "Permission '$required' satisfied by higher-level permission '$higherPermission'"
                        break
                    }
                }
            }
            
            if (-not $hasPermission) {
                $missing += $required
            }
        }
        
        if ($missing.Count -gt 0) {
            $missingList = $missing -join ', '
            Write-Warning "⚠️  Missing required permissions for $ResourceName : $missingList"
            Write-Host "   To resolve: Reconnect with required permissions or use an account with higher privileges" -ForegroundColor Yellow
            
            # Track missing permissions for summary
            foreach ($perm in $missing) {
                if ($script:MissingPermissions -notcontains $perm) {
                    $script:MissingPermissions += $perm
                }
            }
            
            return $false
        }

        return $true
    }
    catch {
        Write-Verbose "Could not decode token to check permissions: $_"
        # If we can't decode, allow the operation to proceed and let the API return an error
        return $true
    }
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
        'Authorization'    = "Bearer $script:GraphAccessToken"
        'Content-Type'     = 'application/json'
        'ConsistencyLevel' = 'eventual'
    }

    $params = @{
        Uri     = $Uri
        Method  = $Method
        Headers = $headers
    }

    if ($Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 10)
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

            if ($result.value) {
                $allItems += $result.value
            }
            elseif ($result) {
                $allItems += $result
            }

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

    for ($i = 0; $i -lt $Requests.Count; $i += $MaxBatchSize) {
        $batchSize = [Math]::Min($MaxBatchSize, $Requests.Count - $i)
        $batches += , @($Requests[$i..($i + $batchSize - 1)])
    }

    Write-Verbose "Processing $($Requests.Count) requests in $($batches.Count) batches"

    foreach ($batch in $batches) {
        $batchBody = @{ requests = $batch }

        try {
            $headers = @{
                'Authorization' = "Bearer $script:GraphAccessToken"
                'Content-Type'  = 'application/json'
            }

            $batchUri = "$script:GraphBaseUrl/`$batch"
            $response = Invoke-RestMethod -Uri $batchUri -Method POST -Headers $headers -Body ($batchBody | ConvertTo-Json -Depth 10) -ErrorAction Stop

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
