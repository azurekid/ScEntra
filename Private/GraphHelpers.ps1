# Module-level shared state and helper utilities for Microsoft Graph interactions

# Module-level variable to store access token
$script:GraphAccessToken = $null
$script:GraphApiVersion = 'v1.0'
$script:GraphBaseUrl = "https://graph.microsoft.com/$script:GraphApiVersion"

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
