function Connect-ScEntraGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph API and obtains an access token

    .DESCRIPTION
        Authenticates to Microsoft Graph using device code flow or existing access token

    .PARAMETER AccessToken
        Existing access token to use for authentication

    .PARAMETER UseDeviceCode
        Use OAuth2 device code flow for interactive authentication using the Microsoft Graph PowerShell client ID. Note: Some organizations may block device code flow for security reasons. Use Azure PowerShell (Connect-AzAccount) or Azure CLI (az login) instead when possible.

    .PARAMETER ClientId
        Custom client ID to use for device code flow authentication. If not specified, uses the Microsoft Graph PowerShell client ID.

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
        [switch]$UseDeviceCode,

        [Parameter(Mandatory = $false)]
        [string]$ClientId,

        [Parameter(Mandatory = $false)]
        [string[]]$Scopes = @(
            "Directory.Read.All",
            "RoleManagement.Read.Directory",
            "RoleEligibilitySchedule.Read.Directory",
            "RoleAssignmentSchedule.Read.Directory",
            "DelegatedPermissionGrant.Read.All"
        ),

        [Parameter(Mandatory = $false)]
        [string]$TenantId = "common"
    )

    # Use Device Code Flow if requested
    if ($UseDeviceCode) {
        Write-Host "`nInitiating OAuth2 Device Code Flow..." -ForegroundColor Cyan
        
        # Use custom client ID if provided, otherwise use Microsoft Graph PowerShell client ID
        $clientId = if ($ClientId) { $ClientId } else { "14d82eec-204b-4c2f-b7e8-296a70dab67e" }
        
        # Build scope string with proper resource prefix
        # Each scope needs to be in the format: https://graph.microsoft.com/.default OR individual scopes with resource prefix
        $scopeString = "https://graph.microsoft.com/.default offline_access"
        
        # Get module version for User-Agent
        $moduleVersion = '1.0.0'
        try {
            $module = Get-Module -Name ScEntra -ErrorAction SilentlyContinue
            if ($module) {
                $moduleVersion = $module.Version.ToString()
            }
        } catch { }
        
        $userAgent = "ScEntra/$moduleVersion (PowerShell/$($PSVersionTable.PSVersion))"
        
        # Request device code
        $deviceCodeRequest = @{
            Uri        = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
            Method     = 'POST'
            UserAgent  = $userAgent
            Body       = @{
                client_id = $clientId
                scope     = $scopeString
            }
        }
        
        try {
            $deviceCodeResponse = Invoke-RestMethod @deviceCodeRequest
            
            Write-Host "`n$($deviceCodeResponse.message)" -ForegroundColor Yellow
            Write-Host "`nWaiting for authentication..." -ForegroundColor Cyan
            
            # Poll for token
            $tokenRequest = @{
                Uri       = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                Method    = 'POST'
                UserAgent = $userAgent
            }
            
            $interval = if ($deviceCodeResponse.interval) { $deviceCodeResponse.interval } else { 5 }
            $expiresAt = (Get-Date).AddSeconds($deviceCodeResponse.expires_in)
            
            while ((Get-Date) -lt $expiresAt) {
                Start-Sleep -Seconds $interval
                
                $tokenRequest['Body'] = @{
                    grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                    client_id   = $clientId
                    device_code = $deviceCodeResponse.device_code
                }
                
                try {
                    $tokenResponse = Invoke-RestMethod @tokenRequest -ErrorAction Stop
                    $script:GraphAccessToken = $tokenResponse.access_token
                    Write-Host "`n✓ Successfully authenticated with device code flow!" -ForegroundColor Green
                    
                    # Validate token has required scopes
                    $tokenInfo = Get-GraphTokenScopeInfo
                    if ($tokenInfo -and $tokenInfo.Scopes) {
                        Write-Verbose "Granted scopes: $($tokenInfo.Scopes -join ', ')"
                        $missingScopes = $Scopes | Where-Object { $_ -notin $tokenInfo.Scopes }
                        if ($missingScopes) {
                            Write-Warning "Some requested scopes were not granted: $($missingScopes -join ', ')"
                        }
                    }
                    return $true
                }
                catch {
                    $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($errorResponse.error -eq 'authorization_pending') {
                        # Still waiting for user to authenticate
                        continue
                    }
                    elseif ($errorResponse.error -eq 'authorization_declined') {
                        Write-Error "Authentication was declined by the user"
                        return $false
                    }
                    elseif ($errorResponse.error -eq 'expired_token') {
                        Write-Error "Device code expired. Please try again."
                        return $false
                    }
                    else {
                        throw
                    }
                }
            }
            
            Write-Error "Device code expired. Please try again."
            return $false
        }
        catch {
            Write-Error "Device code flow failed: $_"
            return $false
        }
    }

    if ($AccessToken) {
        $script:GraphAccessToken = $AccessToken
        Write-Verbose "Using provided access token"
        Write-Host "✓ Access token loaded" -ForegroundColor Green
        
        # Validate token has required scopes
        $tokenInfo = Get-GraphTokenScopeInfo
        if ($tokenInfo -and $tokenInfo.Scopes) {
            Write-Verbose "Token scopes: $($tokenInfo.Scopes -join ', ')"
            $missingScopes = $Scopes | Where-Object { $_ -notin $tokenInfo.Scopes }
            if ($missingScopes) {
                Write-Warning "Provided token is missing required scopes: $($missingScopes -join ', ')"
                Write-Host "Consider using device code flow for full permissions: Connect-ScEntraGraph -UseDeviceCode" -ForegroundColor Yellow
            }
        }
        return $true
    }

    try {
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($azContext) {
            $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction SilentlyContinue
            if ($token) {
                $script:GraphAccessToken = $token.Token | ConvertFrom-SecureString -AsPlainText
                Write-Host "✓ Authenticated using Azure PowerShell context" -ForegroundColor Green
                
                # Validate token has required scopes
                $tokenInfo = Get-GraphTokenScopeInfo
                if ($tokenInfo -and $tokenInfo.Scopes) {
                    Write-Verbose "Token scopes: $($tokenInfo.Scopes -join ', ')"
                    $missingScopes = $Scopes | Where-Object { $_ -notin $tokenInfo.Scopes }
                    if ($missingScopes) {
                        Write-Warning "Azure PowerShell token is missing required scopes: $($missingScopes -join ', ')"
                        Write-Host "Consider using device code flow for full permissions: Connect-ScEntraGraph -UseDeviceCode" -ForegroundColor Yellow
                    }
                }
                return $true
            }
        }
    }
    catch {
        Write-Verbose "Azure PowerShell not available: $_"
    }

    try {
        $cliToken = az account get-access-token --resource https://graph.microsoft.com 2>$null | ConvertFrom-Json
        if ($cliToken -and $cliToken.accessToken) {
            $script:GraphAccessToken = $cliToken.accessToken
            Write-Host "✓ Authenticated using Azure CLI context" -ForegroundColor Green
            
            # Validate token has required scopes
            $tokenInfo = Get-GraphTokenScopeInfo
            if ($tokenInfo -and $tokenInfo.Scopes) {
                Write-Verbose "Token scopes: $($tokenInfo.Scopes -join ', ')"
                $missingScopes = $Scopes | Where-Object { $_ -notin $tokenInfo.Scopes }
                if ($missingScopes) {
                    # Write-Warning "Azure CLI token is missing required scopes: $($missingScopes -join ', ')"
                    Write-Host "Consider using device code flow for full permissions: Connect-ScEntraGraph -UseDeviceCode" -ForegroundColor Yellow
                }
            }
            return $true
        }
    }
    catch {
        Write-Verbose "Azure CLI not available: $_"
    }

    Write-Warning "No existing authentication found. Please authenticate using one of the methods below."
    Write-Host "`nRecommended authentication methods:" -ForegroundColor Yellow
    Write-Host "1. Azure PowerShell: Connect-AzAccount" -ForegroundColor Cyan
    Write-Host "2. Azure CLI: az login" -ForegroundColor Cyan
    Write-Host "3. Provide access token: Connect-ScEntraGraph -AccessToken <token>" -ForegroundColor Cyan
    Write-Host "4. Device Code Flow (if not blocked): Connect-ScEntraGraph -UseDeviceCode" -ForegroundColor Cyan

    return $false
}
